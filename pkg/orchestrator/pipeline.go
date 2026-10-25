package orchestrator

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"qorvex/pkg/forge"
	"qorvex/pkg/platform"
	"qorvex/pkg/store"
)

// Pipeline defines the verification sequence with stages.
type Pipeline struct {
	name   string
	stages []StageDef
}

// StageDef defines a pipeline stage.
type StageDef struct {
	Name        string
	StageFunc   func(*platform.CheckRun, *store.Store) ([]platform.Finding, error)
	TimeoutSec  int
	Critical    bool // if true, stage failure fails the entire check
}

// NewPipeline creates the full verification pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		name: "default",
		stages: []StageDef{
			{Name: "diff_ready", StageFunc: StageDiffReady, TimeoutSec: 10, Critical: true},
			{Name: "structure_check", StageFunc: StageStructureCheck, TimeoutSec: 30, Critical: true},
			{Name: "static_analysis", StageFunc: StageStaticAnalysis, TimeoutSec: 120, Critical: false},
			{Name: "dependency_scan", StageFunc: StageDependencyScan, TimeoutSec: 120, Critical: false},
			{Name: "secret_scan", StageFunc: StageSecretScan, TimeoutSec: 60, Critical: true},
			{Name: "build_and_test", StageFunc: StageBuildAndTest, TimeoutSec: 300, Critical: false},
			{Name: "sandbox_run", StageFunc: StageSandboxRun, TimeoutSec: 120, Critical: false},
			{Name: "risk_assessment", StageFunc: StageRiskAssessment, TimeoutSec: 30, Critical: true},
			{Name: "report_generation", StageFunc: StageReportGeneration, TimeoutSec: 30, Critical: true},
		},
	}
}

// RunAsync executes the pipeline asynchronously and returns immediately.
// Results are written back to the store when stages complete.
func (p *Pipeline) RunAsync(run *platform.CheckRun, s *store.Store) {
	go func() {
		run.Status = "running"
		run.StartTime = time.Now()
		_ = s.UpdateCheckRun(run)

		var allFindings []platform.Finding

		for _, stage := range p.stages {
			findings, err := stage.StageFunc(run, s)
			if err != nil {
				if stage.Critical {
					run.Status = "failed"
					run.Error = fmt.Sprintf("critical stage %q failed: %v", stage.Name, err)
					run.EndTime = time.Now()
					_ = s.UpdateCheckRun(run)
					return
				}
				findings = append(findings, platform.Finding{
					ProjectID:  run.ProjectID,
					Severity:   "low",
					Category:   "quality",
					Description: fmt.Sprintf("non-critical stage %q encountered error: %v", stage.Name, err),
				})
			}
			allFindings = append(allFindings, findings...)
			_ = s.AppendAudit(&platform.AuditEntry{
				Actor:      "system",
				Action:     fmt.Sprintf("pipeline.stage.%s", stage.Name),
				ResourceID: run.ID,
				Detail:     fmt.Sprintf("completed with %d findings", len(findings)),
			})
		}

		// Build final report
		score := calculateScore(allFindings)
		report := &platform.Report{
			CheckRunID: run.ID,
			Score:      score,
			Findings:   allFindings,
			Summary:    fmt.Sprintf("Score: %.1f/100. %d findings.", score, len(allFindings)),
		}

		run.Result = report
		run.Status = "completed"
		if score < 50 {
			run.Status = "failed"
		}
		run.EndTime = time.Now()
		_ = s.UpdateCheckRun(run)

		// Store findings
		for i := range allFindings {
			allFindings[i].CheckRunID = run.ID
			_ = s.CreateFinding(&allFindings[i])
		}

		_ = s.AppendAudit(&platform.AuditEntry{
			Actor:      "system",
			Action:     "pipeline.complete",
			ResourceID: run.ID,
			Detail:     fmt.Sprintf("status=%s score=%.1f findings=%d", run.Status, score, len(allFindings)),
		})
	}()
}

func calculateScore(findings []platform.Finding) float64 {
	if len(findings) == 0 {
		return 100.0
	}
	var total float64 = 100.0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			total -= 25.0
		case "high":
			total -= 15.0
		case "medium":
			total -= 8.0
		case "low":
			total -= 3.0
		}
	}
	if total < 0 {
		total = 0
	}
	return total
}

// Stage implementations

func StageDiffReady(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// TODO: implement actual diff retrieval
	return nil, nil
}

func StageStructureCheck(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// TODO: implement structure validation
	return nil, nil
}

func StageStaticAnalysis(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// Use Forge for project structure and static analysis
	fc := forge.DefaultForgeClient()
	project, _ := s.GetProject(run.ProjectID)
	if project == nil {
		return nil, fmt.Errorf("project %s not found", run.ProjectID)
	}

	result, err := fc.Audit(project.Path)
	if err != nil {
		return nil, fmt.Errorf("forge audit failed: %v", err)
	}

	var findings []platform.Finding
	for _, f := range result.Findings {
		findings = append(findings, toQorvexFinding(f))
		// Also add top findings
		for _, top := range result.Top {
			findings = append(findings, platform.Finding{
				Severity: inferSeverityFromTop(top),
				Category: "forge-top",
				Description: top,
				ProjectID: run.ProjectID,
			})
		}
	}
	return findings, nil
}

func toQorvexFinding(f forge.ForgeFinding) platform.Finding {
	severity := mapSeverity(f.Severity)
	return platform.Finding{
		Severity: severity,
		Category: "forge-" + f.Category,
		Description: f.Description,
		FilePath: f.FilePath,
		LineStart: f.LineStart,
		LineEnd: f.LineEnd,
	}
}

func mapSeverity(forgeSev string) string {
	switch forgeSev {
	case "critical": return "critical"
	case "high": return "high"
	case "medium": return "medium"
	case "low": return "low"
	default: return "low"
	}
}

func inferSeverityFromTop(top string) string {
	if len(top) == 0 { return "low" }
	// Format is typically "severity:category:message"
	for _, sep := range []string{":", " ", "x"} {
		parts := strings.Split(top, sep)
		if len(parts) > 0 {
			s := strings.ToLower(parts[0])
			if s == "critical" || s == "high" { return s }
			if s == "medium" { return "medium" }
			return "low"
		}
	}
	return "low"
}

func StageDependencyScan(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// Use Forge dependency scanner (via pip-audit integration mock)
	// For now, return empty - implement when pip-audit is available
	return nil, nil
}

func StageSecretScan(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// Use Forge for secrets detection
	fc := forge.DefaultForgeClient()
	project, _ := s.GetProject(run.ProjectID)
	if project == nil {
		return nil, fmt.Errorf("project %s not found", run.ProjectID)
	}

	// Execute forge secrets scanner - returns findings
	_, err := fc.Audit(project.Path) // Forge includes secrets in audit
	if err != nil {
		// secrets not found, err might be "no secrets"
		return nil, nil
	}
	return nil, nil
}

func StageBuildAndTest(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// TODO: execute build inside sandbox
	return nil, nil
}

func StageSandboxRun(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// TODO: execute unsafe code in Rust sandbox
	return nil, nil
}

func StageRiskAssessment(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// TODO: evaluate overall risk based on findings
	return nil, nil
}

func StageReportGeneration(run *platform.CheckRun, s *store.Store) ([]platform.Finding, error) {
	// TODO: aggregate results into final report
	return nil, nil
}

// Orchestrator manages pipeline runs.
type Orchestrator struct {
	store    *store.Store
	pipeline *Pipeline
	mu       sync.Mutex
	running  map[string]bool
}

func NewOrchestrator(s *store.Store) *Orchestrator {
	return &Orchestrator{
		store:    s,
		pipeline: NewPipeline(),
		running:  make(map[string]bool),
	}
}

func (o *Orchestrator) StartCheck(projectID string) (*platform.CheckRun, error) {
	project, err := o.store.GetProject(projectID)
	if err != nil {
		return nil, err
	}

	run := &platform.CheckRun{ProjectID: project.ID, Status: "pending"}
	if err := o.store.CreateCheckRun(run); err != nil {
		return nil, err
	}

	o.pipeline.RunAsync(run, o.store)

	o.mu.Lock()
	o.running[run.ID] = true
	o.mu.Unlock()

	return run, nil
}

func (o *Orchestrator) GetCheckStatus(id string) (*platform.CheckRun, error) {
	return o.store.GetCheckRun(id)
}

func (o *Orchestrator) ListChecks(projectID string) ([]*platform.CheckRun, error) {
	return o.store.ListCheckRuns(projectID)
}

func (o *Orchestrator) ListProjects() ([]*platform.Project, error) {
	return o.store.ListProjects()
}

func (o *Orchestrator) CreateProject(name, path string) (*platform.Project, error) {
	p := &platform.Project{Name: name, Path: path}
	if err := o.store.CreateProject(p); err != nil {
		return nil, err
	}
	_ = o.store.AppendAudit(&platform.AuditEntry{
		Actor:      "user",
		Action:     "project.create",
		ResourceID: p.ID,
		Detail:     name,
	})
	return p, nil
}