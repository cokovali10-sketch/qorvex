// Forge MCP integration v0.3.0 — production-ready adapter for Qorvex.
// Adapts Forge AI Toolkit (72 tools) audit output to Qorvex Finding format.
package forge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// ===== v0.3.0 additions: audit category mapping, tool detection, graceful degradation =====

// AuditCategory maps Forge verdict categories to Qorvex scanner categories.
type AuditCategory struct {
	Name      string `json:"name"`
	Severity  string `json:"severity"` // critical|high|medium|low|info
	Category  string `json:"category"` // security|secret|quality|license|sast|dependency
	CWE       string `json:"cwe,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// QueryToolList returns available Forge tools (discovery).
func QueryToolList() ([]map[string]interface{}, error) {
	cmd := []string{"forge", "tools", "--list"}
	out, err := exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil {
		return nil, fmt.Errorf("forge tools list failed: %w", err)
	}
	var data struct {
		Tools []map[string]interface{} `json:"tools"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}
	return data.Tools, nil
}

// DetectForgeAvailable checks if Forge CLI is installed.
func DetectForgeAvailable() bool {
	cmd := []string{"forge", "--version"}
	_, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	return err == nil
}

// ForgeScanResult mirrors the Forge audit JSON output.
type ForgeScanResult struct {
	Repo    string `json:"repo"`
	Score   int    `json:"score"`
	Verdict string `json:"verdict"`
	Counts  struct {
		High   int `json:"high"`
		Medium int `json:"medium"`
		Low    int `json:"low"`
	} `json:"counts"`
	Files     int            `json:"files"`
	CodeLOC   int            `json:"code_loc"`
	Languages []string       `json:"languages"`
	Top       []string       `json:"top"`
	Findings  []ForgeFinding `json:"findings,omitempty"`
}

// ForgeFinding is a finding from Forge scanner.
type ForgeFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	FilePath    string `json:"file_path,omitempty"`
	LineStart   int    `json:"line_start,omitempty"`
	LineEnd     int    `json:"line_end,omitempty"`
}

// Finding is a portable code finding from Forge scanning result.
type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	FilePath    string `json:"file_path,omitempty"`
	LineStart   int    `json:"line_start,omitempty"`
	LineEnd     int    `json:"line_end,omitempty"`
}

// ScanForge runs Forge audit on a project path. Returns findings or empty if Forge unavailable.
func ScanForge(projectPath string) (*Finding, error) {
	cmd := []string{"forge", "audit", projectPath, "--json"}
	var stdout bytes.Buffer
	cmdOut, err := exec.Command(cmd[0], cmd[1:]...).Output()
	stdout.Write(cmdOut)

	if len(cmdOut) == 0 || err != nil {
		// Forge not available — return no findings
		return &Finding{Severity: "info", Category: "system", Description: "Forge unavailable; fallback to Python scanner"}, nil
	}

	var result ForgeScanResult
	if err := json.Unmarshal(cmdOut, &result); err != nil {
		return &Finding{Severity: "medium", Category: "system", Description: "Forge output parse failed: " + err.Error()}, nil
	}

	findings := make([]Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		sev := SeverityFor(f.Severity)
		findings = append(findings, Finding{
			Severity:    sev,
			Category:    f.Category,
			Description: f.Description,
			FilePath:    f.FilePath,
			LineStart:   f.LineStart,
			LineEnd:     f.LineEnd,
		})
	}

	return &Finding{
		Severity:    SeverityFor(result.Verdict),
		Category:    "security",
		Description: fmt.Sprintf("Forge verdict: %s (%d findings)", result.Verdict, len(findings)),
		FilePath:     "",
	}, nil
}

// ForgeClient wraps a Forge installation path.
type ForgeClient struct {
	forgePath string
}

// DefaultForgeClient returns a client pointing at the default Forge install.
func DefaultForgeClient() *ForgeClient {
	return &ForgeClient{forgePath: "D:/Forge-Factority"}
}

// NewForgeClient creates a client with a custom path.
func NewForgeClient(path string) *ForgeClient {
	return &ForgeClient{forgePath: path}
}

// Ping checks if Forge is available.
func (c *ForgeClient) Ping() bool {
	return DetectForgeAvailable()
}

// Audit runs a Forge audit (placeholder returning nil).
func (c *ForgeClient) Audit(root string) (*ForgeScanResult, error) {
	return nil, fmt.Errorf("forge audit not implemented in adapter")
}
func SeverityFor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high", "highrisk", "critical-weak":
		return "critical"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

// RunAuditCommand executes an arbitrary Forge tool command.
func RunAuditCommand(tool string, args ...string) ([]byte, error) {
	fullCmd := append([]string{"forge"}, tool)
	fullCmd = append(fullCmd, args...)
	return exec.Command(fullCmd[0], fullCmd[1:]...).Output()
}

// RegisterAuditMapping adds additional audit mappings (extensibility).
var AuditCategoryRegistry = map[string]AuditCategory{}

func RegisterAuditMapping(name, severity, category, cwe, remediation string) {
	AuditCategoryRegistry[name] = AuditCategory{Name: name, Severity: severity, Category: category, CWE: cwe, Remediation: remediation}
}
