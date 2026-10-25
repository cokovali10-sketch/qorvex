// Forge MCP integration — адаптер для подключения Forge AI Toolkit к Qorvex.
package forge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// ForgeScanResult mirrors the Forge audit JSON output.
type ForgeScanResult struct {
	Repo    string   `json:"repo"`
	Score   int      `json:"score"`
	Verdict string   `json:"verdict"`
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

// ForgeClient communicates with the Forge-Factority MCP server.
type ForgeClient struct {
	forgePath string
}

// NewForgeClient creates a client pointing to the Forge installation.
func NewForgeClient(forgePath string) *ForgeClient {
	return &ForgeClient{forgePath: forgePath}
}

// DefaultForgeClient creates a client at the default Forge path.
func DefaultForgeClient() *ForgeClient {
	return NewForgeClient("D:/Forge-Factority")
}

// Audit runs a full Forge audit and returns findings.
func (f *ForgeClient) Audit(projectPath string) (*ForgeScanResult, error) {
	cmd := exec.Command("python", "-m", "forge.cli", "audit", projectPath, "--json")
	cmd.Dir = f.forgePath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("forge audit failed: %w\nstderr: %s", err, stderr.String())
	}

	var results []ForgeScanResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		return nil, fmt.Errorf("forge parse failed: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("forge returned 0 results")
	}
	return &results[0], nil
}

// Ping checks if forge CLI is available.
func (f *ForgeClient) Ping() bool {
	cmd := exec.Command("python", "-m", "forge.cli", "--version")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}