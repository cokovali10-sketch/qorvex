package orchestrator

import (
	"testing"
	"time"

	"qorvex/pkg/platform"
	"qorvex/pkg/store"
)

func TestNewPipeline(t *testing.T) {
	p := NewPipeline()
	if p == nil {
		t.Fatal("pipeline should not be nil")
	}
	if len(p.stages) != 9 {
		t.Errorf("expected 9 stages, got %d", len(p.stages))
	}

	expectedNames := []string{
		"diff_ready", "structure_check", "static_analysis",
		"dependency_scan", "secret_scan", "build_and_test",
		"sandbox_run", "risk_assessment", "report_generation",
	}
	for i, s := range p.stages {
		if s.Name != expectedNames[i] {
			t.Errorf("stage %d: expected %s, got %s", i, expectedNames[i], s.Name)
		}
	}
}

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []platform.Finding
		want     float64
	}{
		{"no findings", nil, 100.0},
		{"empty", []platform.Finding{}, 100.0},
		{"low", []platform.Finding{{Severity: "low"}}, 97.0},
		{"medium", []platform.Finding{{Severity: "medium"}}, 92.0},
		{"high", []platform.Finding{{Severity: "high"}}, 85.0},
		{"critical", []platform.Finding{{Severity: "critical"}}, 75.0},
		{"mixed", []platform.Finding{
			{Severity: "critical"}, {Severity: "high"},
			{Severity: "medium"}, {Severity: "low"},
		}, 49.0},
		{"many critical", []platform.Finding{
			{Severity: "critical"}, {Severity: "critical"},
			{Severity: "critical"}, {Severity: "critical"},
			{Severity: "critical"},
		}, 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateScore(tt.findings)
			if got != tt.want {
				t.Errorf("calculateScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewOrchestrator(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)
	if o == nil {
		t.Fatal("orchestrator should not be nil")
	}
}

func TestCreateProject(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)

	p, err := o.CreateProject("test-project", "/tmp/test")
	if err != nil {
		t.Fatalf("CreateProject() error: %v", err)
	}
	if p.Name != "test-project" {
		t.Errorf("expected name %q, got %q", "test-project", p.Name)
	}
	if p.ID == "" {
		t.Error("ID should be set")
	}
}

func TestListProjects(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)

	projects, _ := o.ListProjects()
	initial := len(projects)

	o.CreateProject("p1", ".")
	o.CreateProject("p2", ".")

	projects, _ = o.ListProjects()
	if len(projects) != initial+2 {
		t.Errorf("expected %d projects, got %d", initial+2, len(projects))
	}
}

func TestStartCheckNoProject(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)

	_, err := o.StartCheck("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent project")
	}
}

func TestStartCheck(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)

	p, _ := o.CreateProject("test", "/tmp/test")
	run, err := o.StartCheck(p.ID)
	if err != nil {
		t.Fatalf("StartCheck() error: %v", err)
	}
	if run.ProjectID != p.ID {
		t.Errorf("expected project ID %s, got %s", p.ID, run.ProjectID)
	}
	if run.Status != "pending" {
		t.Errorf("expected pending, got %s", run.Status)
	}
}

func TestGetCheckStatus(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)

	_, err := o.GetCheckStatus("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent check")
	}
}

func TestStageFunctions(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*platform.CheckRun, *store.Store) ([]platform.Finding, error)
	}{
		{"StageDiffReady", StageDiffReady},
		{"StageStructureCheck", StageStructureCheck},
		{"StageStaticAnalysis", StageStaticAnalysis},
		{"StageDependencyScan", StageDependencyScan},
		{"StageSecretScan", StageSecretScan},
		{"StageBuildAndTest", StageBuildAndTest},
		{"StageSandboxRun", StageSandboxRun},
		{"StageRiskAssessment", StageRiskAssessment},
		{"StageReportGeneration", StageReportGeneration},
	}

	s := store.New()
	run := &platform.CheckRun{ID: "test", ProjectID: "proj-test"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := tt.fn(run, s)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if len(findings) > 0 {
				t.Errorf("expected 0 findings from stub, got %d", len(findings))
			}
		})
	}
}

func TestPipelineAsync(t *testing.T) {
	s := store.New()
	o := NewOrchestrator(s)

	p, _ := o.CreateProject("test-async", ".")
	run := &platform.CheckRun{
		ProjectID: p.ID,
		Status:    "pending",
	}
	s.CreateCheckRun(run)

	o.pipeline.RunAsync(run, s)

	// Poll with small delays for goroutine to execute
	var got *platform.CheckRun
	var err error
	for i := 0; i < 100; i++ {
		got, err = o.GetCheckStatus(run.ID)
		if err != nil {
			continue
		}
		if got.Status != "pending" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pipeline async goroutine did not execute within timeout, status=%s", got.Status)
}

func TestStageSecretsBlocks(t *testing.T) {
	s := store.New()
	run := &platform.CheckRun{ID: "test", ProjectID: "proj-test"}
	findings, err := StageSecretScan(run, s)
	if err != nil {
		t.Errorf("secret scan failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from stub, got %d", len(findings))
	}
}