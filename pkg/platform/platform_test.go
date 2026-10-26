package platform

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewDefaultSandboxConfig(t *testing.T) {
	cfg := NewDefaultSandboxConfig()
	if cfg.MemoryMB != 512 {
		t.Errorf("expected 512 MB, got %d", cfg.MemoryMB)
	}
	if cfg.TimeoutSec != 60 {
		t.Errorf("expected 60s timeout, got %d", cfg.TimeoutSec)
	}
	if !cfg.NetworkBlock {
		t.Error("network should be blocked by default")
	}
	if !cfg.ReadonlyFS {
		t.Error("filesystem should be readonly by default")
	}
}

func TestProjectJSONRoundrip(t *testing.T) {
	p := &Project{
		ID:   "proj-1",
		Name: "Test",
		Path: "/tmp/test",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var p2 Project
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if p2.Name != p.Name {
		t.Errorf("expected %s, got %s", p.Name, p2.Name)
	}
}

func TestCheckRunTransitions(t *testing.T) {
	r := &CheckRun{
		ID:        "chk-test",
		ProjectID: "proj-test",
		Status:    "pending",
	}
	if r.Status != "pending" {
		t.Errorf("expected pending, got %s", r.Status)
	}

	r.Status = "running"
	r.StartTime = time.Now()
	if r.Status != "running" {
		t.Errorf("expected running, got %s", r.Status)
	}

	r.Status = "completed"
	r.EndTime = time.Now()
	if r.Status != "completed" {
		t.Errorf("expected completed, got %s", r.Status)
	}
}

func TestFindingSeverityLevels(t *testing.T) {
	f := &Finding{Severity: "critical", Category: "security", Description: "test"}
	if f.Severity != "critical" {
		t.Errorf("expected critical, got %s", f.Severity)
	}
}

func TestPolicyDefaultFrozen(t *testing.T) {
	p := &Policy{
		Name:    "test",
		Version: 1,
		Frozen:  false,
		Rules: []Rule{
			{ID: "r1", Severity: "block", Category: "security", Pattern: "critical", Description: "block critical"},
		},
	}
	if p.Frozen == true {
		t.Error("default policy should not be frozen")
	}
	if len(p.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(p.Rules))
	}
}

func TestSandboxConfigDefaults(t *testing.T) {
	cfg := NewDefaultSandboxConfig()
	if cfg.User != "nobody" {
		t.Errorf("expected nobody user, got %s", cfg.User)
	}
	if cfg.MaxFiles != 128 {
		t.Errorf("expected 128 max files, got %d", cfg.MaxFiles)
	}
}

func TestAuditEntrySignature(t *testing.T) {
	e := &AuditEntry{
		Actor:  "test",
		Action: "test.action",
	}
	if e.ID != "" {
		t.Error("ID should be empty before append")
	}
}

func TestReportStructure(t *testing.T) {
	r := &Report{
		ID:    "rpt-1",
		Score: 85.5,
		Findings: []Finding{
			{Severity: "low", Category: "quality", Description: "minor issue"},
		},
		Summary: "85.5/100",
	}
	if r.Score != 85.5 {
		t.Errorf("expected 85.5, got %f", r.Score)
	}
	if len(r.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(r.Findings))
	}
}
