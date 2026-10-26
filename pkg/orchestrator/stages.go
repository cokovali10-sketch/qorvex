package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"qorvex/pkg/forge"
	"qorvex/pkg/platform"
	"qorvex/pkg/store"
)

// StageContext carries everything a stage may read or write. Findings holds
// the accumulated results of previous stages, so risk assessment and report
// generation can reason over the whole run.
type StageContext struct {
	Run      *platform.CheckRun
	Store    *store.Store
	Findings []platform.Finding
	Meta     map[string]any
	Deadline time.Time
}

// StageFunc is the signature of a pipeline stage.
type StageFunc func(*StageContext) ([]platform.Finding, error)

// commandTimeout returns the smaller of the stage budget and fallback.
func (c *StageContext) commandTimeout(fallback time.Duration) time.Duration {
	if c == nil || c.Deadline.IsZero() {
		return fallback
	}
	remaining := time.Until(c.Deadline)
	if remaining <= 0 {
		return time.Millisecond
	}
	if remaining < fallback {
		return remaining
	}
	return fallback
}

// infoFinding builds a non-scoring informational finding.
func infoFinding(ctx *StageContext, category, description string) platform.Finding {
	return platform.Finding{
		ProjectID:   ctx.Run.ProjectID,
		CheckRunID:  ctx.Run.ID,
		Severity:    "info",
		Category:    category,
		Description: description,
	}
}

// projectFromCtx loads and validates the project under inspection.
func projectFromCtx(ctx *StageContext) (*platform.Project, string, error) {
	if ctx == nil || ctx.Run == nil {
		return nil, "", errors.New("stage context is missing the check run")
	}
	if ctx.Store == nil {
		return nil, "", errors.New("stage context is missing the store")
	}
	p, err := ctx.Store.GetProject(ctx.Run.ProjectID)
	if err != nil {
		return nil, "", err
	}
	root, err := resolveProjectRoot(p)
	if err != nil {
		return nil, "", err
	}
	return p, root, nil
}

// ---------------------------------------------------------------------------
// Stage 1 — diff readiness
// ---------------------------------------------------------------------------

// StageDiffReady verifies that the project is readable and records the VCS
// state so later stages know whether diff-scoped checks are possible.
func StageDiffReady(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	ctx.Meta["project_root"] = root

	gitDir := filepath.Join(root, ".git")
	if !dirExists(gitDir) && !fileExists(gitDir) {
		return []platform.Finding{
			infoFinding(ctx, "diff", "no git repository detected; verification runs against the full tree"),
		}, nil
	}

	res := runCommand(ctx.commandTimeout(10*time.Second), root, "git", "status", "--porcelain")
	if res.Err != nil {
		return []platform.Finding{
			infoFinding(ctx, "diff", "git repository detected; working tree status unavailable"),
		}, nil
	}

	changed := countNonEmptyLines(res.Stdout)
	return []platform.Finding{
		infoFinding(ctx, "diff", fmt.Sprintf("git repository detected; %d changed path(s) in the working tree", changed)),
	}, nil
}

// ---------------------------------------------------------------------------
// Stage 2 — structure check
// ---------------------------------------------------------------------------

// StageStructureCheck walks the tree under strict bounds and flags files that
// are unsafe to analyse, such as symlinks escaping the project root.
func StageStructureCheck(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	files, truncated, err := walkProject(root, maxScanFiles)
	if err != nil {
		return nil, fmt.Errorf("walk project: %w", err)
	}
	ctx.Meta["files"] = files
	ctx.Meta["files_truncated"] = truncated

	var findings []platform.Finding
	for _, f := range files {
		if f.Mode&os.ModeSymlink != 0 {
			target, linkErr := filepath.EvalSymlinks(f.Abs)
			if linkErr != nil || !isWithin(root, target) {
				findings = append(findings, platform.Finding{
					ProjectID:   ctx.Run.ProjectID,
					CheckRunID:  ctx.Run.ID,
					Severity:    "high",
					Category:    "security",
					Description: fmt.Sprintf("symlink escapes project root: %s", f.Rel),
					FilePath:    f.Rel,
					RuleID:      "structure-symlink-escape",
				})
			}
		}
		if f.Size > 10<<20 {
			findings = append(findings, platform.Finding{
				ProjectID:   ctx.Run.ProjectID,
				CheckRunID:  ctx.Run.ID,
				Severity:    "low",
				Category:    "quality",
				Description: fmt.Sprintf("oversized file (%d bytes) skipped by content scanners", f.Size),
				FilePath:    f.Rel,
				RuleID:      "structure-large-file",
			})
		}
	}

	if truncated {
		findings = append(findings, platform.Finding{
			ProjectID:   ctx.Run.ProjectID,
			CheckRunID:  ctx.Run.ID,
			Severity:    "medium",
			Category:    "quality",
			Description: fmt.Sprintf("file limit reached (%d); scan results cover a subset of the tree", maxScanFiles),
			RuleID:      "structure-truncated",
		})
	}

	findings = append(findings, infoFinding(ctx, "structure", fmt.Sprintf("inspected %d file(s)", len(files))))
	return findings, nil
}

// ---------------------------------------------------------------------------
// Stage 3 — static analysis
// ---------------------------------------------------------------------------

// StageStaticAnalysis prefers Forge for project-wide analysis and falls back
// to the bundled Python scanner when Forge is not installed.
func StageStaticAnalysis(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if fc := forge.DefaultForgeClient(); fc.Ping() {
		result, auditErr := fc.Audit(root)
		if auditErr == nil && result != nil {
			ctx.Meta["static_engine"] = "forge"
			findings := forgeFindings(result, ctx.Run.ProjectID, ctx.Run.ID)
			if len(findings) == 0 {
				findings = append(findings, infoFinding(ctx, "sast", "forge audit completed with no findings"))
			}
			return findings, nil
		}
	}

	findings, scanErr := scanWithPython(ctx, root)
	if scanErr == nil {
		ctx.Meta["static_engine"] = "python"
		if len(findings) == 0 {
			findings = append(findings, infoFinding(ctx, "sast", "python scanner completed with no findings"))
		}
		return findings, nil
	}

	ctx.Meta["static_engine"] = "none"
	return []platform.Finding{
		infoFinding(ctx, "sast", fmt.Sprintf("static analysis skipped: forge and python scanner unavailable (%v)", scanErr)),
	}, nil
}

// forgeFindings converts a Forge audit into platform findings exactly once.
func forgeFindings(result *forge.ForgeScanResult, projectID, checkRunID string) []platform.Finding {
	findings := make([]platform.Finding, 0, len(result.Findings)+len(result.Top))
	for _, f := range result.Findings {
		findings = append(findings, platform.Finding{
			ProjectID:   projectID,
			CheckRunID:  checkRunID,
			Severity:    mapSeverity(f.Severity),
			Category:    "forge-" + f.Category,
			Description: f.Description,
			FilePath:    f.FilePath,
			LineStart:   f.LineStart,
			LineEnd:     f.LineEnd,
			RuleID:      "forge-" + f.Category,
		})
	}
	for _, top := range result.Top {
		findings = append(findings, platform.Finding{
			ProjectID:   projectID,
			CheckRunID:  checkRunID,
			Severity:    inferSeverityFromTop(top),
			Category:    "forge-top",
			Description: top,
			RuleID:      "forge-top",
		})
	}
	return findings
}

func mapSeverity(forgeSev string) string {
	switch strings.ToLower(forgeSev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "low"
	}
}

func inferSeverityFromTop(top string) string {
	if top == "" {
		return "low"
	}
	first := strings.ToLower(strings.TrimSpace(strings.SplitN(top, ":", 2)[0]))
	switch {
	case strings.Contains(first, "critical"):
		return "critical"
	case strings.Contains(first, "high"):
		return "high"
	case strings.Contains(first, "medium"), strings.Contains(first, "moderate"):
		return "medium"
	default:
		return "low"
	}
}

// pyFinding mirrors the Python scanner's JSON finding schema.
type pyFinding struct {
	Severity    string  `json:"severity"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	FilePath    *string `json:"file_path"`
	LineStart   *int    `json:"line_start"`
	LineEnd     *int    `json:"line_end"`
	CWE         *string `json:"cwe"`
	Remediation *string `json:"remediation"`
	RuleID      *string `json:"rule_id"`
}

type pyScanResult struct {
	ScannerName string      `json:"scanner_name"`
	Findings    []pyFinding `json:"findings"`
	Errors      []string    `json:"errors"`
}

// scanWithPython invokes the bundled scanner CLI against root.
func scanWithPython(ctx *StageContext, root string) ([]platform.Finding, error) {
	pyDir, ok := findRepoSubdir("python")
	if !ok {
		return nil, errors.New("python scanner directory not found")
	}
	if !toolAvailable("python") {
		return nil, errors.New("python interpreter not found")
	}

	res := runCommand(ctx.commandTimeout(120*time.Second), pyDir, "python", "-m", "scanners.cli", "scan", root, "--format", "json")
	// The scanner exits 1 when high/critical findings exist; the payload is
	// still valid, so parse stdout whenever it contains JSON.
	if strings.TrimSpace(res.Stdout) == "" {
		if res.Err != nil {
			return nil, fmt.Errorf("python scanner failed: %v", res.Err)
		}
		return nil, errors.New("python scanner produced no output")
	}

	var results []pyScanResult
	if err := json.Unmarshal([]byte(res.Stdout), &results); err != nil {
		return nil, fmt.Errorf("parse python scanner output: %w", err)
	}

	var findings []platform.Finding
	for _, r := range results {
		for _, f := range r.Findings {
			pf := platform.Finding{
				ProjectID:   ctx.Run.ProjectID,
				CheckRunID:  ctx.Run.ID,
				Severity:    normalizeSeverity(f.Severity),
				Category:    f.Category,
				Description: f.Description,
			}
			if f.FilePath != nil {
				if rel, err := filepath.Rel(root, *f.FilePath); err == nil {
					pf.FilePath = rel
				} else {
					pf.FilePath = *f.FilePath
				}
			}
			if f.LineStart != nil {
				pf.LineStart = *f.LineStart
			}
			if f.LineEnd != nil {
				pf.LineEnd = *f.LineEnd
			}
			if f.CWE != nil {
				pf.CWE = *f.CWE
			}
			if f.Remediation != nil {
				pf.Remediation = *f.Remediation
			}
			if f.RuleID != nil {
				pf.RuleID = *f.RuleID
			}
			findings = append(findings, pf)
		}
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Stage 4 — dependency scan
// ---------------------------------------------------------------------------

type manifestInfo struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

var manifestCandidates = []manifestInfo{
	{Kind: "go", Path: "go.mod"},
	{Kind: "npm", Path: "package.json"},
	{Kind: "npm", Path: "package-lock.json"},
	{Kind: "python", Path: "requirements.txt"},
	{Kind: "python", Path: "pyproject.toml"},
	{Kind: "python", Path: "setup.py"},
	{Kind: "rust", Path: "Cargo.toml"},
	{Kind: "java", Path: "pom.xml"},
	{Kind: "java", Path: "build.gradle"},
	{Kind: "ruby", Path: "Gemfile"},
	{Kind: "php", Path: "composer.json"},
}

// detectManifests returns dependency manifests present at the project root.
func detectManifests(root string) []manifestInfo {
	var found []manifestInfo
	for _, m := range manifestCandidates {
		if fileExists(filepath.Join(root, m.Path)) {
			found = append(found, m)
		}
	}
	return found
}

// StageDependencyScan runs whichever dependency auditors are installed and
// reports vulnerabilities with a stable severity mapping.
func StageDependencyScan(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	manifests := detectManifests(root)
	ctx.Meta["manifests"] = manifests
	if len(manifests) == 0 {
		return []platform.Finding{
			infoFinding(ctx, "dependency", "no dependency manifests detected"),
		}, nil
	}

	kinds := map[string]bool{}
	for _, m := range manifests {
		kinds[m.Kind] = true
	}

	var findings []platform.Finding
	var ran, skipped []string

	if kinds["go"] && toolAvailable("govulncheck") {
		res := runCommand(ctx.commandTimeout(90*time.Second), root, "govulncheck", "./...")
		if res.Err == nil {
			findings = append(findings, parseGovulncheck(res.Stdout, ctx)...)
			ran = append(ran, "govulncheck")
		} else {
			skipped = append(skipped, "govulncheck (failed)")
		}
	} else if kinds["go"] {
		skipped = append(skipped, "govulncheck (not installed)")
	}

	if kinds["npm"] && fileExists(filepath.Join(root, "package-lock.json")) && toolAvailable("npm") {
		res := runCommand(ctx.commandTimeout(90*time.Second), root, "npm", "audit", "--json", "--audit-level=low")
		if strings.TrimSpace(res.Stdout) != "" {
			if parsed, ok := parseNpmAudit(res.Stdout, ctx); ok {
				findings = append(findings, parsed...)
				ran = append(ran, "npm audit")
			} else {
				skipped = append(skipped, "npm audit (unparsable)")
			}
		} else {
			skipped = append(skipped, "npm audit (failed)")
		}
	} else if kinds["npm"] {
		skipped = append(skipped, "npm audit (lockfile or npm missing)")
	}

	if kinds["python"] && fileExists(filepath.Join(root, "requirements.txt")) && toolAvailable("pip-audit") {
		res := runCommand(ctx.commandTimeout(90*time.Second), root, "pip-audit", "-r", "requirements.txt", "-f", "json")
		if parsed, ok := parsePipAudit(res.Stdout, ctx); ok {
			findings = append(findings, parsed...)
			ran = append(ran, "pip-audit")
		} else {
			skipped = append(skipped, "pip-audit (failed)")
		}
	} else if kinds["python"] {
		skipped = append(skipped, "pip-audit (not installed or no requirements.txt)")
	}

	if kinds["rust"] && toolAvailable("cargo") {
		res := runCommand(ctx.commandTimeout(90*time.Second), root, "cargo", "audit", "--json")
		if parsed, ok := parseCargoAudit(res.Stdout, ctx); ok {
			findings = append(findings, parsed...)
			ran = append(ran, "cargo audit")
		} else {
			skipped = append(skipped, "cargo audit (not installed)")
		}
	} else if kinds["rust"] {
		skipped = append(skipped, "cargo audit (cargo missing)")
	}

	summary := fmt.Sprintf("dependency scan: %d manifest(s)", len(manifests))
	if len(ran) > 0 {
		summary += "; ran: " + strings.Join(ran, ", ")
	}
	if len(skipped) > 0 {
		summary += "; skipped: " + strings.Join(skipped, ", ")
	}
	findings = append(findings, infoFinding(ctx, "dependency", summary))
	return findings, nil
}

func parseNpmAudit(out string, ctx *StageContext) ([]platform.Finding, bool) {
	var data struct {
		Vulnerabilities map[string]struct {
			Severity string            `json:"severity"`
			Via      []json.RawMessage `json:"via"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return nil, false
	}

	names := make([]string, 0, len(data.Vulnerabilities))
	for name := range data.Vulnerabilities {
		names = append(names, name)
	}
	sort.Strings(names)

	findings := make([]platform.Finding, 0, len(names))
	for _, name := range names {
		v := data.Vulnerabilities[name]
		description := "known vulnerability in dependency"
		for _, raw := range v.Via {
			var title struct {
				Title string `json:"title"`
			}
			if err := json.Unmarshal(raw, &title); err == nil && title.Title != "" {
				description = title.Title
				break
			}
			var plain string
			if err := json.Unmarshal(raw, &plain); err == nil && plain != "" {
				description = plain
				break
			}
		}
		findings = append(findings, platform.Finding{
			ProjectID:   ctx.Run.ProjectID,
			CheckRunID:  ctx.Run.ID,
			Severity:    normalizeSeverity(v.Severity),
			Category:    "dependency",
			Description: fmt.Sprintf("%s: %s", name, description),
			Remediation: "update the affected package to a patched version",
			RuleID:      "npm:" + name,
		})
		if len(findings) >= 200 {
			break
		}
	}
	return findings, true
}

func parsePipAudit(out string, ctx *StageContext) ([]platform.Finding, bool) {
	var data []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			FixVersions []string `json:"fix_versions"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return nil, false
	}

	var findings []platform.Finding
	for _, pkg := range data {
		for _, v := range pkg.Vulns {
			remediation := "upgrade the package"
			if len(v.FixVersions) > 0 {
				remediation = "upgrade to " + strings.Join(v.FixVersions, ", ")
			}
			findings = append(findings, platform.Finding{
				ProjectID:   ctx.Run.ProjectID,
				CheckRunID:  ctx.Run.ID,
				Severity:    "medium",
				Category:    "dependency",
				Description: fmt.Sprintf("%s %s: %s (%s)", pkg.Name, pkg.Version, v.ID, truncate(v.Description, 160)),
				Remediation: remediation,
				RuleID:      "pip-audit:" + v.ID,
			})
		}
	}
	return findings, true
}

func parseCargoAudit(out string, ctx *StageContext) ([]platform.Finding, bool) {
	var data struct {
		Vulnerabilities struct {
			List []struct {
				Advisory struct {
					ID          string          `json:"id"`
					Title       string          `json:"title"`
					Description string          `json:"description"`
					Severity    json.RawMessage `json:"severity"`
				} `json:"advisory"`
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
			} `json:"list"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return nil, false
	}

	var findings []platform.Finding
	for _, v := range data.Vulnerabilities.List {
		severity := "medium"
		var sev string
		if err := json.Unmarshal(v.Advisory.Severity, &sev); err == nil {
			severity = normalizeSeverity(sev)
		}
		findings = append(findings, platform.Finding{
			ProjectID:   ctx.Run.ProjectID,
			CheckRunID:  ctx.Run.ID,
			Severity:    severity,
			Category:    "dependency",
			Description: fmt.Sprintf("%s %s: %s (%s)", v.Package.Name, v.Package.Version, v.Advisory.ID, truncate(v.Advisory.Title, 160)),
			Remediation: "upgrade the affected crate",
			RuleID:      "cargo-audit:" + v.Advisory.ID,
		})
	}
	return findings, true
}

func parseGovulncheck(out string, ctx *StageContext) []platform.Finding {
	var findings []platform.Finding
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Vulnerability #") {
			continue
		}
		findings = append(findings, platform.Finding{
			ProjectID:   ctx.Run.ProjectID,
			CheckRunID:  ctx.Run.ID,
			Severity:    "medium",
			Category:    "dependency",
			Description: truncate(line, 200),
			Remediation: "upgrade the affected module",
			RuleID:      "govulncheck",
		})
		if len(findings) >= 100 {
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Stage 5 — secret scan
// ---------------------------------------------------------------------------

type secretRule struct {
	ID          string
	Severity    string
	Category    string
	Description string
	Pattern     *regexp.Regexp
	Generic     bool
}

var secretRules = []secretRule{
	{
		ID:          "aws-access-key",
		Severity:    "critical",
		Category:    "secret",
		Description: "AWS access key ID detected",
		Pattern:     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		ID:          "aws-secret-key",
		Severity:    "critical",
		Category:    "secret",
		Description: "AWS secret access key assignment detected",
		Pattern:     regexp.MustCompile(`(?i)aws_?secret_?access_?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?`),
	},
	{
		ID:          "private-key",
		Severity:    "critical",
		Category:    "secret",
		Description: "private key material detected",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
	},
	{
		ID:          "github-token",
		Severity:    "high",
		Category:    "secret",
		Description: "GitHub token detected",
		Pattern:     regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
	},
	{
		ID:          "slack-token",
		Severity:    "high",
		Category:    "secret",
		Description: "Slack token detected",
		Pattern:     regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	},
	{
		ID:          "google-api-key",
		Severity:    "high",
		Category:    "secret",
		Description: "Google API key detected",
		Pattern:     regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	},
	{
		ID:          "jwt",
		Severity:    "medium",
		Category:    "secret",
		Description: "JSON Web Token detected",
		Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	},
	{
		ID:          "generic-secret",
		Severity:    "medium",
		Category:    "secret",
		Description: "hardcoded credential assignment detected",
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|api[_-]?key|secret|token)\s*[=:]\s*["'][^"'\s]{8,}["']`),
		Generic:     true,
	},
}

var placeholderMarkers = []string{
	"example", "sample", "dummy", "placeholder", "changeme", "change_me",
	"your_", "your-", "xxxx", "****", "${", "{{", "redacted", "todo",
}

// StageSecretScan runs high-signal credential rules over bounded text files.
func StageSecretScan(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	files, ok := ctx.Meta["files"].([]projectFile)
	if !ok || files == nil {
		files, _, err = walkProject(root, maxScanFiles)
		if err != nil {
			return nil, fmt.Errorf("walk project: %w", err)
		}
	}

	seen := map[string]bool{}
	var findings []platform.Finding
	scanned := 0

	for _, f := range files {
		if f.Mode&os.ModeSymlink != 0 || f.Size > maxScanFileBytes {
			continue
		}
		data, readErr := readFileBounded(f.Abs, maxScanFileBytes)
		if readErr != nil || looksBinary(data) {
			continue
		}
		scanned++

		content := string(data)
		for _, rule := range secretRules {
			for _, loc := range rule.Pattern.FindAllStringIndex(content, 100) {
				match := content[loc[0]:loc[1]]
				if rule.Generic && isPlaceholder(match) {
					continue
				}
				line := lineNumber(content, loc[0])
				key := fmt.Sprintf("%s|%s|%d", rule.ID, f.Rel, line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, platform.Finding{
					ProjectID:   ctx.Run.ProjectID,
					CheckRunID:  ctx.Run.ID,
					Severity:    rule.Severity,
					Category:    rule.Category,
					Description: rule.Description,
					FilePath:    f.Rel,
					LineStart:   line,
					LineEnd:     line,
					RuleID:      rule.ID,
					Remediation: "remove the credential from source and rotate it",
				})
			}
		}
	}

	if len(findings) == 0 {
		return []platform.Finding{
			infoFinding(ctx, "secret", fmt.Sprintf("no secrets detected in %d text file(s)", scanned)),
		}, nil
	}
	return findings, nil
}

func isPlaceholder(match string) bool {
	lower := strings.ToLower(match)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// lineNumber returns the 1-based line containing byte offset.
func lineNumber(content string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(content) {
		offset = len(content)
	}
	return strings.Count(content[:offset], "\n") + 1
}

// ---------------------------------------------------------------------------
// Stage 6 — build and test
// ---------------------------------------------------------------------------

// detectBuildSystem returns the build system used at root, if any.
func detectBuildSystem(root string) string {
	switch {
	case fileExists(filepath.Join(root, "go.mod")):
		return "go"
	case fileExists(filepath.Join(root, "Cargo.toml")):
		return "cargo"
	case fileExists(filepath.Join(root, "package.json")):
		return "npm"
	case fileExists(filepath.Join(root, "pyproject.toml")),
		fileExists(filepath.Join(root, "setup.py")),
		fileExists(filepath.Join(root, "requirements.txt")):
		return "python"
	default:
		return ""
	}
}

// StageBuildAndTest compiles the project with whichever toolchain is
// installed. Missing toolchains are reported, never silently ignored.
func StageBuildAndTest(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	system := detectBuildSystem(root)
	ctx.Meta["build_system"] = system
	if system == "" {
		return []platform.Finding{
			infoFinding(ctx, "build", "no supported build system detected"),
		}, nil
	}

	var tool string
	var args []string
	switch system {
	case "go":
		tool, args = "go", []string{"build", "./..."}
	case "cargo":
		tool, args = "cargo", []string{"check", "--quiet"}
	case "npm":
		if !dirExists(filepath.Join(root, "node_modules")) {
			return []platform.Finding{
				infoFinding(ctx, "build", "npm build skipped: dependencies are not installed"),
			}, nil
		}
		tool, args = "npm", []string{"run", "build", "--if-present"}
	case "python":
		tool, args = "python", []string{"-m", "compileall", "-q", "."}
	}

	if !toolAvailable(tool) {
		return []platform.Finding{
			infoFinding(ctx, "build", fmt.Sprintf("build skipped: %s toolchain not installed", tool)),
		}, nil
	}

	res := runCommand(ctx.commandTimeout(180*time.Second), root, tool, args...)
	if res.Err != nil {
		detail := truncate(strings.TrimSpace(res.Stderr+"\n"+res.Stdout), 500)
		if detail == "" {
			detail = res.Err.Error()
		}
		return []platform.Finding{{
			ProjectID:   ctx.Run.ProjectID,
			CheckRunID:  ctx.Run.ID,
			Severity:    "high",
			Category:    "quality",
			Description: fmt.Sprintf("%s build failed: %s", system, detail),
			RuleID:      "build-failed",
		}}, nil
	}

	return []platform.Finding{
		infoFinding(ctx, "build", fmt.Sprintf("%s build passed", system)),
	}, nil
}

// ---------------------------------------------------------------------------
// Stage 7 — sandbox execution
// ---------------------------------------------------------------------------

type sandboxSpec struct {
	Command    []string `json:"command"`
	TimeoutSec int      `json:"timeout_sec"`
	Network    bool     `json:"network"`
}

// loadSandboxSpec reads .qorvex/sandbox.json from the project root.
func loadSandboxSpec(root string) (*sandboxSpec, error) {
	path, err := safeJoin(root, filepath.Join(".qorvex", "sandbox.json"))
	if err != nil {
		return nil, err
	}
	data, err := readFileBounded(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var spec sandboxSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse sandbox spec: %w", err)
	}
	if len(spec.Command) == 0 {
		return nil, errors.New("sandbox spec has no command")
	}
	return &spec, nil
}

// findSandboxBinary locates the Rust sandbox runner.
func findSandboxBinary() (string, bool) {
	if env := os.Getenv("QORVEX_SANDBOX_BIN"); env != "" && fileExists(env) {
		return env, true
	}
	for _, name := range []string{"qorvex-sandbox", "qorvex-sandbox.exe"} {
		if p, err := lookPath(name); err == nil {
			return p, true
		}
	}
	if rustDir, ok := findRepoSubdir("rust"); ok {
		for _, rel := range []string{
			"target/release/qorvex-sandbox.exe",
			"target/release/qorvex-sandbox",
			"target/debug/qorvex-sandbox.exe",
			"target/debug/qorvex-sandbox",
		} {
			p := filepath.Join(rustDir, rel)
			if fileExists(p) {
				return p, true
			}
		}
	}
	return "", false
}

// StageSandboxRun executes an explicitly configured command inside the Rust
// sandbox. Absent configuration is reported, never guessed.
func StageSandboxRun(ctx *StageContext) ([]platform.Finding, error) {
	_, root, err := projectFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	spec, specErr := loadSandboxSpec(root)
	if specErr != nil {
		return []platform.Finding{
			infoFinding(ctx, "sandbox", fmt.Sprintf("sandbox run skipped: no usable .qorvex/sandbox.json (%v)", specErr)),
		}, nil
	}

	binary, ok := findSandboxBinary()
	if !ok {
		return []platform.Finding{
			infoFinding(ctx, "sandbox", "sandbox run skipped: qorvex-sandbox binary not built"),
		}, nil
	}

	timeout := 60 * time.Second
	if spec.TimeoutSec > 0 && spec.TimeoutSec <= 600 {
		timeout = time.Duration(spec.TimeoutSec) * time.Second
	}
	if budget := ctx.commandTimeout(timeout); budget < timeout {
		timeout = budget
	}

	res := runCommand(timeout, root, binary, spec.Command...)
	if res.Err != nil {
		return []platform.Finding{{
			ProjectID:   ctx.Run.ProjectID,
			CheckRunID:  ctx.Run.ID,
			Severity:    "high",
			Category:    "sandbox",
			Description: fmt.Sprintf("sandbox command failed: %s", truncate(res.Stderr+" "+res.Stdout, 400)),
			RuleID:      "sandbox-failed",
		}}, nil
	}

	return []platform.Finding{
		infoFinding(ctx, "sandbox", "sandbox command completed successfully"),
	}, nil
}

// ---------------------------------------------------------------------------
// Stage 8 — risk assessment
// ---------------------------------------------------------------------------

// severityCounts tallies findings by severity.
func severityCounts(findings []platform.Finding) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		if _, ok := counts[f.Severity]; ok {
			counts[f.Severity]++
		} else {
			counts["info"]++
		}
	}
	return counts
}

// riskFromFindings derives an overall risk level from severity counts.
func riskFromFindings(findings []platform.Finding) string {
	counts := severityCounts(findings)
	switch {
	case counts["critical"] > 0:
		return "critical"
	case counts["high"] > 0, counts["medium"] >= 5:
		return "high"
	case counts["medium"] > 0, counts["low"] >= 5:
		return "medium"
	default:
		return "low"
	}
}

// StageRiskAssessment records the aggregate risk level for later stages.
func StageRiskAssessment(ctx *StageContext) ([]platform.Finding, error) {
	risk := riskFromFindings(ctx.Findings)
	counts := severityCounts(ctx.Findings)
	ctx.Meta["risk_level"] = risk
	ctx.Meta["severity_counts"] = counts

	return []platform.Finding{
		infoFinding(ctx, "risk", fmt.Sprintf(
			"risk level: %s (critical=%d high=%d medium=%d low=%d)",
			risk, counts["critical"], counts["high"], counts["medium"], counts["low"],
		)),
	}, nil
}

// ---------------------------------------------------------------------------
// Stage 9 — report generation
// ---------------------------------------------------------------------------

// buildReport assembles the final report from accumulated findings.
func buildReport(run *platform.CheckRun, findings []platform.Finding, meta map[string]any) *platform.Report {
	score := calculateScore(findings)
	counts := severityCounts(findings)

	risk, _ := meta["risk_level"].(string)
	if risk == "" {
		risk = riskFromFindings(findings)
	}

	sbom := ""
	if manifests, ok := meta["manifests"].([]manifestInfo); ok && len(manifests) > 0 {
		if data, err := json.MarshalIndent(manifests, "", "  "); err == nil {
			sbom = string(data)
		}
	}

	return &platform.Report{
		CheckRunID:     run.ID,
		Score:          score,
		RiskLevel:      risk,
		SeverityCounts: counts,
		Findings:       findings,
		Summary: fmt.Sprintf(
			"Score %.1f/100; risk %s; %d finding(s): %d critical, %d high, %d medium, %d low",
			score, risk, len(findings), counts["critical"], counts["high"], counts["medium"], counts["low"],
		),
		SBOM: sbom,
	}
}

// StageReportGeneration finalises the report. RunAsync uses the report set
// here instead of rebuilding it.
func StageReportGeneration(ctx *StageContext) ([]platform.Finding, error) {
	if ctx == nil || ctx.Run == nil {
		return nil, errors.New("stage context is missing the check run")
	}
	ctx.Run.Result = buildReport(ctx.Run, ctx.Findings, ctx.Meta)
	return nil, nil
}

// normalizeSeverity maps external scanner severities onto Qorvex levels.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "moderate", "warning", "warn":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "note":
		return "info"
	default:
		return "medium"
	}
}

// countNonEmptyLines counts lines that contain at least one non-space byte.
func countNonEmptyLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// dedupeFindings removes exact duplicates while preserving order.
func dedupeFindings(findings []platform.Finding) []platform.Finding {
	seen := make(map[string]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := fmt.Sprintf("%s|%s|%s|%s|%d", f.Severity, f.Category, f.FilePath, f.Description, f.LineStart)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
