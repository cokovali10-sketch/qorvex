package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qorvex/pkg/platform"
	"qorvex/pkg/store"
)

// newStageFixture creates a store, a temp project and a check run.
func newStageFixture(t *testing.T, files map[string]string) (*store.Store, *platform.CheckRun, string) {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := store.New()
	p := &platform.Project{Name: "fixture", Path: dir}
	if err := s.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	run := &platform.CheckRun{ID: "chk-test", ProjectID: p.ID}
	return s, run, dir
}

func newCtx(s *store.Store, run *platform.CheckRun, findings []platform.Finding) *StageContext {
	return &StageContext{
		Run:      run,
		Store:    s,
		Findings: findings,
		Meta:     map[string]any{},
		Deadline: time.Now().Add(2 * time.Minute),
	}
}

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()

	got, err := safeJoin(root, filepath.Join("a", "b.txt"))
	if err != nil {
		t.Fatalf("safeJoin() error: %v", err)
	}
	if !strings.HasPrefix(got, root) {
		t.Errorf("joined path %q is outside root %q", got, root)
	}

	if _, err := safeJoin(root, ".."+string(filepath.Separator)+"escape.txt"); err == nil {
		t.Error("expected traversal to be rejected")
	}

	abs := filepath.Join(root, "abs.txt")
	if _, err := safeJoin(root, abs); err == nil {
		t.Error("expected absolute path to be rejected")
	}
}

func TestIsWithin(t *testing.T) {
	root := filepath.Join("work", "proj")
	if !isWithin(root, filepath.Join(root, "a", "b")) {
		t.Error("descendant should be within root")
	}
	if isWithin(root, filepath.Join("work", "proj-evil", "a")) {
		t.Error("sibling with shared prefix must not be within root")
	}
	if isWithin(root, "work") {
		t.Error("ancestor must not be within root")
	}
}

func TestWalkProjectSkipsNoisyDirs(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "main.go"), "package main")
	mustWrite(t, filepath.Join(dir, "node_modules", "dep.js"), "x")
	mustWrite(t, filepath.Join(dir, ".git", "config"), "x")
	mustWrite(t, filepath.Join(dir, "src", "app.py"), "print(1)")

	files, truncated, err := walkProject(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("did not expect truncation")
	}

	rels := map[string]bool{}
	for _, f := range files {
		rels[f.Rel] = true
	}
	if !rels["main.go"] || !rels[filepath.Join("src", "app.py")] {
		t.Errorf("expected source files, got %v", rels)
	}
	for rel := range rels {
		if strings.Contains(rel, "node_modules") || strings.Contains(rel, ".git") {
			t.Errorf("noisy path should be skipped: %s", rel)
		}
	}
}

func TestWalkProjectTruncates(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		mustWrite(t, filepath.Join(dir, "f"+string(rune('a'+i))+".txt"), "x")
	}
	files, truncated, err := walkProject(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("expected truncation flag")
	}
	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d", len(files))
	}
}

func TestReadFileBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	mustWrite(t, path, "hello")

	data, err := readFileBounded(path, 100)
	if err != nil || string(data) != "hello" {
		t.Fatalf("readFileBounded() = %q, %v", data, err)
	}

	big := filepath.Join(dir, "big.txt")
	mustWrite(t, big, strings.Repeat("a", 200))
	if _, err := readFileBounded(big, 100); err == nil {
		t.Error("expected error for oversized file")
	}
}

func TestLooksBinary(t *testing.T) {
	if looksBinary([]byte("plain text")) {
		t.Error("text should not be binary")
	}
	if !looksBinary([]byte{0x00, 0x01, 0x02}) {
		t.Error("NUL bytes should be binary")
	}
}

func TestResolveProjectRoot(t *testing.T) {
	dir := t.TempDir()
	root, err := resolveProjectRoot(&platform.Project{Path: dir})
	if err != nil {
		t.Fatalf("resolveProjectRoot() error: %v", err)
	}
	if !dirExists(root) {
		t.Errorf("resolved root does not exist: %s", root)
	}

	if _, err := resolveProjectRoot(&platform.Project{Path: ""}); err == nil {
		t.Error("empty path must fail")
	}
	if _, err := resolveProjectRoot(nil); err == nil {
		t.Error("nil project must fail")
	}
}

func TestStageDiffReadyNoGit(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{"a.txt": "x"})
	findings, err := StageDiffReady(newCtx(s, run, nil))
	if err != nil {
		t.Fatalf("StageDiffReady() error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != "info" {
		t.Errorf("expected one info finding, got %+v", findings)
	}
}

func TestStageStructureCheckSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	mustWrite(t, target, "secret")

	link := filepath.Join(dir, "escape")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	s := store.New()
	p := &platform.Project{Name: "symlink", Path: dir}
	if err := s.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	run := &platform.CheckRun{ID: "chk", ProjectID: p.ID}

	findings, err := StageStructureCheck(newCtx(s, run, nil))
	if err != nil {
		t.Fatalf("StageStructureCheck() error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "structure-symlink-escape" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected symlink escape finding, got %+v", findings)
	}
}

func TestStageSecretScanDetectsAWSAccessKey(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{
		"config.py": "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n",
	})
	findings, err := StageSecretScan(newCtx(s, run, nil))
	if err != nil {
		t.Fatalf("StageSecretScan() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].Severity != "critical" || findings[0].RuleID != "aws-access-key" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
	if findings[0].LineStart != 1 {
		t.Errorf("expected line 1, got %d", findings[0].LineStart)
	}
}

func TestStageSecretScanDetectsPrivateKey(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{
		"id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
	})
	findings, err := StageSecretScan(newCtx(s, run, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "private-key" {
		t.Fatalf("expected private-key finding, got %+v", findings)
	}
}

func TestStageSecretScanIgnoresPlaceholders(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{
		"config.py": "password = \"changeme_please\"\napi_key = \"your_api_key_here\"\n",
	})
	findings, err := StageSecretScan(newCtx(s, run, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Severity != "info" {
			t.Errorf("placeholder should not produce a finding: %+v", f)
		}
	}
}

func TestStageSecretScanCleanProject(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{"main.go": "package main\n"})
	findings, err := StageSecretScan(newCtx(s, run, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != "info" {
		t.Errorf("expected clean info finding, got %+v", findings)
	}
}

func TestDetectManifests(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module x")
	mustWrite(t, filepath.Join(dir, "package.json"), "{}")
	mustWrite(t, filepath.Join(dir, "requirements.txt"), "")

	manifests := detectManifests(dir)
	kinds := map[string]bool{}
	for _, m := range manifests {
		kinds[m.Kind] = true
	}
	if !kinds["go"] || !kinds["npm"] || !kinds["python"] {
		t.Errorf("expected go/npm/python manifests, got %+v", manifests)
	}
}

func TestStageDependencyScanNoManifests(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{"a.txt": "x"})
	findings, err := StageDependencyScan(newCtx(s, run, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != "info" {
		t.Errorf("expected one info finding, got %+v", findings)
	}
}

func TestParseNpmAudit(t *testing.T) {
	out := `{"vulnerabilities":{"lodash":{"severity":"high","via":[{"title":"Prototype Pollution"}]}}}`
	ctx := &StageContext{Run: &platform.CheckRun{ID: "c", ProjectID: "p"}}
	findings, ok := parseNpmAudit(out, ctx)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected one parsed finding, got %+v (ok=%v)", findings, ok)
	}
	if findings[0].Severity != "high" || !strings.Contains(findings[0].Description, "lodash") {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestParsePipAudit(t *testing.T) {
	out := `[{"name":"requests","version":"2.0.0","vulns":[{"id":"GHSA-1","description":"bad","fix_versions":["2.1.0"]}]}]`
	ctx := &StageContext{Run: &platform.CheckRun{ID: "c", ProjectID: "p"}}
	findings, ok := parsePipAudit(out, ctx)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected one parsed finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Remediation, "2.1.0") {
		t.Errorf("expected remediation, got %+v", findings[0])
	}
}

func TestParseCargoAudit(t *testing.T) {
	out := `{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-1","title":"bad","severity":"high"},"package":{"name":"crate","version":"0.1.0"}}]}}`
	ctx := &StageContext{Run: &platform.CheckRun{ID: "c", ProjectID: "p"}}
	findings, ok := parseCargoAudit(out, ctx)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected one parsed finding, got %+v", findings)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high, got %s", findings[0].Severity)
	}
}

func TestParseGovulncheck(t *testing.T) {
	out := "Vulnerability #1: GO-2024-0001\n  More info: https://pkg.go.dev/vuln/GO-2024-0001\n"
	ctx := &StageContext{Run: &platform.CheckRun{ID: "c", ProjectID: "p"}}
	findings := parseGovulncheck(out, ctx)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical",
		"High":     "high",
		"moderate": "medium",
		"warning":  "medium",
		"low":      "low",
		"info":     "info",
		"weird":    "medium",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRiskFromFindings(t *testing.T) {
	if got := riskFromFindings(nil); got != "low" {
		t.Errorf("expected low, got %s", got)
	}
	if got := riskFromFindings([]platform.Finding{{Severity: "critical"}}); got != "critical" {
		t.Errorf("expected critical, got %s", got)
	}
	if got := riskFromFindings([]platform.Finding{{Severity: "high"}}); got != "high" {
		t.Errorf("expected high, got %s", got)
	}
	if got := riskFromFindings([]platform.Finding{{Severity: "medium"}}); got != "medium" {
		t.Errorf("expected medium, got %s", got)
	}
}

func TestBuildReport(t *testing.T) {
	run := &platform.CheckRun{ID: "chk-1"}
	findings := []platform.Finding{
		{Severity: "high"},
		{Severity: "low"},
	}
	meta := map[string]any{"risk_level": "high"}

	report := buildReport(run, findings, meta)
	if report.CheckRunID != "chk-1" {
		t.Errorf("unexpected check run id: %s", report.CheckRunID)
	}
	if report.Score != 82.0 {
		t.Errorf("expected score 82, got %v", report.Score)
	}
	if report.RiskLevel != "high" {
		t.Errorf("expected high risk, got %s", report.RiskLevel)
	}
	if report.SeverityCounts["high"] != 1 || report.SeverityCounts["low"] != 1 {
		t.Errorf("unexpected counts: %+v", report.SeverityCounts)
	}
}

func TestDedupeFindings(t *testing.T) {
	in := []platform.Finding{
		{Severity: "high", Category: "security", FilePath: "a", Description: "d", LineStart: 1},
		{Severity: "high", Category: "security", FilePath: "a", Description: "d", LineStart: 1},
		{Severity: "low", Category: "quality", FilePath: "b", Description: "e"},
	}
	out := dedupeFindings(in)
	if len(out) != 2 {
		t.Errorf("expected 2 findings, got %d", len(out))
	}
}

func TestLoadSandboxSpec(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".qorvex", "sandbox.json"), `{"command":["echo","hi"],"timeout_sec":5}`)

	spec, err := loadSandboxSpec(dir)
	if err != nil {
		t.Fatalf("loadSandboxSpec() error: %v", err)
	}
	if len(spec.Command) != 2 || spec.TimeoutSec != 5 {
		t.Errorf("unexpected spec: %+v", spec)
	}

	empty := t.TempDir()
	if _, err := loadSandboxSpec(empty); err == nil {
		t.Error("expected error for missing spec")
	}

	bad := t.TempDir()
	mustWrite(t, filepath.Join(bad, ".qorvex", "sandbox.json"), `{"command":[]}`)
	if _, err := loadSandboxSpec(bad); err == nil {
		t.Error("expected error for empty command")
	}
}

func TestStageSandboxRunWithoutConfig(t *testing.T) {
	s, run, _ := newStageFixture(t, map[string]string{"a.txt": "x"})
	findings, err := StageSandboxRun(newCtx(s, run, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != "info" {
		t.Errorf("expected info skip finding, got %+v", findings)
	}
}

func TestLineNumber(t *testing.T) {
	content := "one\ntwo\nthree"
	if got := lineNumber(content, 0); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
	if got := lineNumber(content, 4); got != 2 {
		t.Errorf("expected 2, got %d", got)
	}
	if got := lineNumber(content, len(content)); got != 3 {
		t.Errorf("expected 3, got %d", got)
	}
}

func TestIsPlaceholder(t *testing.T) {
	if !isPlaceholder(`password = "changeme"`) {
		t.Error("changeme should be a placeholder")
	}
	if isPlaceholder(`AKIAIOSFODNN7REALKEY`) {
		t.Error("real-looking key is not a placeholder")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("unexpected truncate result: %q", got)
	}
	if got := truncate("  hi  ", 10); got != "hi" {
		t.Errorf("expected trimmed value, got %q", got)
	}
}

func TestCountNonEmptyLines(t *testing.T) {
	if got := countNonEmptyLines("a\n\n b \n"); got != 2 {
		t.Errorf("expected 2, got %d", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
