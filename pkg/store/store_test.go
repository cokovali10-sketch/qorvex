package store

import (
	"testing"
	"time"

	"qorvex/pkg/platform"
)

func TestNewStore(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("store should not be nil")
	}
}

func TestCreateProject(t *testing.T) {
	s := New()
	p := &platform.Project{Name: "Test", Path: "/tmp/test"}
	err := s.CreateProject(p)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if p.ID == "" {
		t.Error("ID should be set after creation")
	}
	if p.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set after creation")
	}
}

func TestListProjects(t *testing.T) {
	s := New()
	projects, err := s.ListProjects()
	if err != nil {
		t.Errorf("list failed: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("expected 0, got %d", len(projects))
	}

	s.CreateProject(&platform.Project{Name: "A", Path: "."})
	projects, _ = s.ListProjects()
	if len(projects) != 1 {
		t.Errorf("expected 1, got %d", len(projects))
	}
}

func TestGetProject(t *testing.T) {
	s := New()
	p := &platform.Project{Name: "P", Path: "."}
	s.CreateProject(p)

	got, err := s.GetProject(p.ID)
	if err != nil {
		t.Errorf("get failed: %v", err)
	}
	if got.Name != "P" {
		t.Errorf("expected P, got %s", got.Name)
	}
}

func TestGetProjectNotFound(t *testing.T) {
	s := New()
	_, err := s.GetProject("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent project")
	}
}

func TestCreateCheckRun(t *testing.T) {
	s := New()
	s.CreateProject(&platform.Project{Name: "P", Path: "."})

	r := &platform.CheckRun{ProjectID: "proj-fake"}
	err := s.CreateCheckRun(r)
	if err != nil {
		t.Errorf("create check run failed: %v", err)
	}
	if r.ID == "" {
		t.Error("ID should be set")
	}
}

func TestUpdateCheckRun(t *testing.T) {
	s := New()
	s.CreateProject(&platform.Project{Name: "P", Path: "."})

	r := &platform.CheckRun{ProjectID: "proj-fake"}
	s.CreateCheckRun(r)
	r.Status = "completed"
	r.EndTime = time.Now()

	err := s.UpdateCheckRun(r)
	if err != nil {
		t.Errorf("update failed: %v", err)
	}

	got, _ := s.GetCheckRun(r.ID)
	if got.Status != "completed" {
		t.Errorf("expected completed, got %s", got.Status)
	}
}

func TestCreateFinding(t *testing.T) {
	s := New()
	f := &platform.Finding{
		ProjectID:   "proj-1",
		Severity:    "high",
		Category:    "security",
		Description: "test finding",
	}
	err := s.CreateFinding(f)
	if err != nil {
		t.Errorf("create finding failed: %v", err)
	}
	if f.ID == "" {
		t.Error("ID should be set")
	}
}

func TestGetFindings(t *testing.T) {
	s := New()
	s.CreateFinding(&platform.Finding{ProjectID: "proj-1", Severity: "high", Category: "security", Description: "f1"})
	s.CreateFinding(&platform.Finding{ProjectID: "proj-1", Severity: "low", Category: "quality", Description: "f2"})
	s.CreateFinding(&platform.Finding{ProjectID: "proj-2", Severity: "medium", Category: "security", Description: "f3"})

	findings, _ := s.GetFindings("proj-1")
	if len(findings) != 2 {
		t.Errorf("expected 2 findings for proj-1, got %d", len(findings))
	}

	findings2, _ := s.GetFindings("proj-nonexistent")
	if len(findings2) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings2))
	}
}

func TestAppendAudit(t *testing.T) {
	s := New()
	entry := &platform.AuditEntry{
		Actor:      "user1",
		Action:     "project.create",
		ResourceID: "proj-1",
		Detail:     "test",
	}
	err := s.AppendAudit(entry)
	if err != nil {
		t.Errorf("append audit failed: %v", err)
	}
	if entry.ID == "" {
		t.Error("ID should be set")
	}
	if entry.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestListAudit(t *testing.T) {
	s := New()
	s.AppendAudit(&platform.AuditEntry{Actor: "a", Action: "action1", ResourceID: "r1", Detail: "d1"})
	s.AppendAudit(&platform.AuditEntry{Actor: "b", Action: "action2", ResourceID: "r2", Detail: "d2"})

	entries, _ := s.ListAudit(10)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	// Test limit
	entries2, _ := s.ListAudit(1)
	if len(entries2) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries2))
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := New()
	done := make(chan bool)

	go func() {
		for i := 0; i < 10; i++ {
			s.CreateProject(&platform.Project{Name: "A", Path: "."})
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 10; i++ {
			s.ListProjects()
		}
		done <- true
	}()

	<-done
	<-done
}

func TestStoreReturnsCopies(t *testing.T) {
	s := New()
	p := &platform.Project{Name: "P", Path: "."}
	s.CreateProject(p)

	got, _ := s.GetProject(p.ID)
	got.Name = "mutated"
	again, _ := s.GetProject(p.ID)
	if again.Name != "P" {
		t.Errorf("store leaked a mutable project pointer: %s", again.Name)
	}

	r := &platform.CheckRun{
		ProjectID: p.ID,
		Result: &platform.Report{
			Score:          90,
			Findings:       []platform.Finding{{Severity: "low"}},
			SeverityCounts: map[string]int{"low": 1},
		},
		Stages: []platform.Stage{{Name: "diff_ready", Status: "completed"}},
	}
	s.CreateCheckRun(r)

	run, _ := s.GetCheckRun(r.ID)
	run.Result.Score = 0
	run.Result.Findings[0].Severity = "critical"
	run.Result.SeverityCounts["low"] = 99
	run.Stages[0].Status = "failed"

	stored, _ := s.GetCheckRun(r.ID)
	if stored.Result.Score != 90 {
		t.Errorf("report score was mutated: %v", stored.Result.Score)
	}
	if stored.Result.Findings[0].Severity != "low" {
		t.Errorf("finding was mutated: %s", stored.Result.Findings[0].Severity)
	}
	if stored.Result.SeverityCounts["low"] != 1 {
		t.Errorf("severity counts were mutated: %v", stored.Result.SeverityCounts)
	}
	if stored.Stages[0].Status != "completed" {
		t.Errorf("stage was mutated: %s", stored.Stages[0].Status)
	}

	f := &platform.Finding{ProjectID: p.ID, Severity: "high", Category: "security", Description: "x"}
	s.CreateFinding(f)
	findings, _ := s.GetFindings(p.ID)
	findings[0].Severity = "info"
	againFindings, _ := s.GetFindings(p.ID)
	if againFindings[0].Severity != "high" {
		t.Errorf("finding pointer leaked: %s", againFindings[0].Severity)
	}
}

func TestUpdateCheckRunSnapshots(t *testing.T) {
	s := New()
	r := &platform.CheckRun{ProjectID: "p"}
	s.CreateCheckRun(r)

	r.Status = "completed"
	if err := s.UpdateCheckRun(r); err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's copy after Update must not change stored state.
	r.Status = "failed"
	stored, _ := s.GetCheckRun(r.ID)
	if stored.Status != "completed" {
		t.Errorf("expected completed snapshot, got %s", stored.Status)
	}
}
