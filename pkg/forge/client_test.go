package forge

import (
	"encoding/json"
	"testing"
)

func TestDefaultForgeClient(t *testing.T) {
	c := DefaultForgeClient()
	if c.forgePath != "D:/Forge-Factority" {
		t.Errorf("expected D:/Forge-Factority, got %s", c.forgePath)
	}
}

func TestForgeClientCustomPath(t *testing.T) {
	c := NewForgeClient("/custom/path")
	if c.forgePath != "/custom/path" {
		t.Errorf("expected /custom/path, got %s", c.forgePath)
	}
}

func TestForgeScanResultJSON(t *testing.T) {
	r := &ForgeScanResult{
		Repo:    "test",
		Score:   85,
		Verdict: "ok",
		Files:   10,
		CodeLOC: 500,
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var r2 ForgeScanResult
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if r2.Score != 85 {
		t.Errorf("expected 85, got %d", r2.Score)
	}
}

func TestForgeFindingJSON(t *testing.T) {
	f := ForgeFinding{
		Severity:    "critical",
		Category:    "security",
		Description: "SQL injection",
		FilePath:    "app.py",
		LineStart:   42,
		LineEnd:     45,
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var f2 ForgeFinding
	if err := json.Unmarshal(data, &f2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if f2.Severity != "critical" {
		t.Errorf("expected critical, got %s", f2.Severity)
	}
	if f2.LineStart != 42 {
		t.Errorf("expected 42, got %d", f2.LineStart)
	}
}

func TestForgeScanResultEmpty(t *testing.T) {
	r := &ForgeScanResult{}
	if r.Score != 0 {
		t.Errorf("expected 0, got %d", r.Score)
	}
}

func TestForgeFindingEmpty(t *testing.T) {
	f := ForgeFinding{}
	if f.Severity != "" {
		t.Errorf("expected empty, got %s", f.Severity)
	}
	if f.LineStart != 0 {
		t.Errorf("expected 0, got %d", f.LineStart)
	}
}

func TestFindingStructure(t *testing.T) {
	f := Finding{
		Severity:    "high",
		Category:    "forge-security",
		Description: "credential leak",
		FilePath:    "config.py",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var f2 Finding
	if err := json.Unmarshal(data, &f2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if f2.Severity != "high" {
		t.Errorf("expected high, got %s", f2.Severity)
	}
}

func TestForgeScanResultWithFindings(t *testing.T) {
	r := &ForgeScanResult{
		Findings: []ForgeFinding{
			{Severity: "low", Category: "quality", Description: "naming"},
			{Severity: "medium", Category: "style", Description: "formatting"},
		},
	}
	if len(r.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(r.Findings))
	}
}

func TestForgeClientPing(t *testing.T) {
	c := NewForgeClient("/invalid/path")
	alive := c.Ping()
	if alive {
		t.Log("forge CLI is available on this system")
	}
}

func TestForgeScanResultScore(t *testing.T) {
	r := &ForgeScanResult{Score: 100}
	if r.Score != 100 {
		t.Errorf("expected 100, got %d", r.Score)
	}
}

func TestForgeScanResultLanguages(t *testing.T) {
	r := &ForgeScanResult{
		Languages: []string{"go", "python", "rust"},
	}
	if len(r.Languages) != 3 {
		t.Errorf("expected 3 languages, got %d", len(r.Languages))
	}
}

func TestForgeScanResultTopFindings(t *testing.T) {
	r := &ForgeScanResult{
		Top: []string{"critical:security:rce", "high:secret:cred"},
	}
	if len(r.Top) != 2 {
		t.Errorf("expected 2 top findings, got %d", len(r.Top))
	}
}
