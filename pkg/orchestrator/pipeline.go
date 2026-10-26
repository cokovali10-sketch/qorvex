package orchestrator

import (
	"fmt"
	"sync"
	"time"

	"qorvex/pkg/audit"
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
	Name       string
	StageFunc  StageFunc
	TimeoutSec int
	Critical   bool // if true, stage failure fails the entire check
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
//
// Stages are synchronous: each stage must bound its own I/O using
// StageContext.Deadline. The budget is re-checked after every stage so a
// stage that ignores its deadline still fails closed.
func (p *Pipeline) RunAsync(run *platform.CheckRun, s *store.Store, auditors ...*audit.Logger) {
	var auditor *audit.Logger
	if len(auditors) > 0 {
		auditor = auditors[0]
	}

	go func() {
		// Work on a private copy: the caller's pointer is never mutated, so
		// API responses cannot race with pipeline progress.
		run = run.Clone()
		run.Status = "running"
		run.StartTime = time.Now()
		run.Stages = make([]platform.Stage, 0, len(p.stages))
		_ = s.UpdateCheckRun(run)

		meta := map[string]any{}
		var allFindings []platform.Finding

		for _, stage := range p.stages {
			stageStart := time.Now()
			deadline := stageStart.Add(time.Duration(stage.TimeoutSec) * time.Second)
			ctx := &StageContext{
				Run:      run,
				Store:    s,
				Findings: allFindings,
				Meta:     meta,
				Deadline: deadline,
			}

			findings, err := stage.StageFunc(ctx)
			if err == nil && time.Now().After(deadline) {
				err = fmt.Errorf("stage exceeded its %ds budget", stage.TimeoutSec)
			}

			record := platform.Stage{
				Name:      stage.Name,
				StartTime: stageStart,
				EndTime:   time.Now(),
			}

			if err != nil && stage.Critical {
				record.Status = "failed"
				record.Error = err.Error()
				run.Stages = append(run.Stages, record)
				run.Status = "failed"
				run.Error = fmt.Sprintf("critical stage %q failed: %v", stage.Name, err)
				run.EndTime = time.Now()
				_ = s.UpdateCheckRun(run)
				appendAudit(s, auditor, &platform.AuditEntry{
					Actor:      "system",
					Action:     "pipeline.failed",
					ResourceID: run.ID,
					Detail:     fmt.Sprintf("stage=%s error=%v", stage.Name, err),
				})
				return
			}

			if err != nil {
				record.Status = "completed_with_errors"
				record.Error = err.Error()
				findings = append(findings, platform.Finding{
					ProjectID:   run.ProjectID,
					CheckRunID:  run.ID,
					Severity:    "low",
					Category:    "quality",
					Description: fmt.Sprintf("non-critical stage %q encountered an error: %v", stage.Name, err),
					RuleID:      "stage-error:" + stage.Name,
				})
			} else {
				record.Status = "completed"
			}
			run.Stages = append(run.Stages, record)

			for i := range findings {
				if findings[i].ProjectID == "" {
					findings[i].ProjectID = run.ProjectID
				}
				if findings[i].CheckRunID == "" {
					findings[i].CheckRunID = run.ID
				}
			}
			allFindings = append(allFindings, findings...)
			_ = s.UpdateCheckRun(run)

			appendAudit(s, auditor, &platform.AuditEntry{
				Actor:      "system",
				Action:     fmt.Sprintf("pipeline.stage.%s", stage.Name),
				ResourceID: run.ID,
				Detail:     fmt.Sprintf("status=%s findings=%d", record.Status, len(findings)),
			})
		}

		// Deduplicate before scoring so duplicated scanner output cannot
		// inflate the penalty.
		allFindings = dedupeFindings(allFindings)
		for i := range allFindings {
			allFindings[i].ProjectID = run.ProjectID
			allFindings[i].CheckRunID = run.ID
		}

		if run.Result == nil {
			run.Result = buildReport(run, allFindings, meta)
		} else {
			run.Result.CheckRunID = run.ID
			run.Result.Findings = allFindings
			run.Result.Score = calculateScore(allFindings)
			run.Result.SeverityCounts = severityCounts(allFindings)
			if run.Result.RiskLevel == "" {
				run.Result.RiskLevel = riskFromFindings(allFindings)
			}
			run.Result.Summary = fmt.Sprintf(
				"Score %.1f/100; risk %s; %d finding(s): %d critical, %d high, %d medium, %d low",
				run.Result.Score, run.Result.RiskLevel, len(allFindings),
				run.Result.SeverityCounts["critical"], run.Result.SeverityCounts["high"],
				run.Result.SeverityCounts["medium"], run.Result.SeverityCounts["low"],
			)
		}

		// Fail closed: a critical risk blocks the check even when the
		// weighted score alone would remain above the threshold.
		run.Status = "completed"
		if run.Result.Score < 50 || run.Result.RiskLevel == "critical" {
			run.Status = "failed"
		}
		run.EndTime = time.Now()
		_ = s.UpdateCheckRun(run)

		for i := range allFindings {
			_ = s.CreateFinding(&allFindings[i])
		}

		appendAudit(s, auditor, &platform.AuditEntry{
			Actor:      "system",
			Action:     "pipeline.complete",
			ResourceID: run.ID,
			Detail:     fmt.Sprintf("status=%s score=%.1f risk=%s findings=%d", run.Status, run.Result.Score, run.Result.RiskLevel, len(allFindings)),
		})
	}()
}

// appendAudit writes to the store log and, when configured, to the signed
// HMAC audit log used by the API.
func appendAudit(s *store.Store, al *audit.Logger, entry *platform.AuditEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_ = s.AppendAudit(entry)
	if al != nil {
		copied := *entry
		_ = al.Append(&copied)
	}
}

// calculateScore computes a score from 0 to 100 based on findings severity.
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

// Orchestrator manages pipeline runs.
type Orchestrator struct {
	store    *store.Store
	auditor  *audit.Logger
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

// SetAuditor attaches the signed audit log used by the API.
func (o *Orchestrator) SetAuditor(al *audit.Logger) {
	o.auditor = al
}

func (o *Orchestrator) StartCheck(projectID string) (*platform.CheckRun, error) {
	project, err := o.store.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	// Validate the project root synchronously so callers get an immediate
	// error instead of an asynchronously failed check.
	if _, err := resolveProjectRoot(project); err != nil {
		return nil, err
	}

	run := &platform.CheckRun{ProjectID: project.ID, Status: "pending"}
	if err := o.store.CreateCheckRun(run); err != nil {
		return nil, err
	}

	o.pipeline.RunAsync(run, o.store, o.auditor)

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
	appendAudit(o.store, o.auditor, &platform.AuditEntry{
		Actor:      "user",
		Action:     "project.create",
		ResourceID: p.ID,
		Detail:     name,
	})
	return p, nil
}

// resolveProjectRoot canonicalises a project path and fails fast if the path
// is empty, missing, or not a directory.  Used in StartCheck to reject bad
// project roots before a pipeline goroutine is launched.
