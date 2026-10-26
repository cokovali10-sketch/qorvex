package platform

import "time"

// Project represents a codebase under inspection.
type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CheckRun represents a single verification run.
type CheckRun struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Status    string    `json:"status"` // "pending", "running", "completed", "failed"
	Result    *Report   `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
	Stages    []Stage   `json:"stages,omitempty"`
}

// Stage represents a pipeline stage execution record.
type Stage struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Error     string    `json:"error,omitempty"`
}

// Report aggregates all findings from a check run.
type Report struct {
	ID             string         `json:"id"`
	CheckRunID     string         `json:"check_run_id"`
	Score          float64        `json:"score"`
	RiskLevel      string         `json:"risk_level,omitempty"` // "low", "medium", "high", "critical"
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	Findings       []Finding      `json:"findings"`
	Summary        string         `json:"summary"`
	SBOM           string         `json:"sbom,omitempty"`
}

// Finding is a security issue or code quality problem.
type Finding struct {
	ID          string `json:"id"`
	CheckRunID  string `json:"check_run_id"`
	ProjectID   string `json:"project_id"`
	Severity    string `json:"severity"` // "critical", "high", "medium", "low", "info"
	Category    string `json:"category"` // "security", "quality", "dependency", "secret"
	Description string `json:"description"`
	FilePath    string `json:"file_path,omitempty"`
	LineStart   int    `json:"line_start,omitempty"`
	LineEnd     int    `json:"line_end,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
}

// Diff represents a code change between two versions.
type Diff struct {
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	OldPath    string `json:"old_path"`
	NewPath    string `json:"new_path"`
	OldContent string `json:"old_content,omitempty"`
	NewContent string `json:"new_content,omitempty"`
}

// SandboxConfig describes the execution environment.
type SandboxConfig struct {
	Namespace    string         `json:"namespace"`
	User         string         `json:"user"`
	MemoryMB     int            `json:"memory_mb"`
	CPUShares    int            `json:"cpu_shares"`
	TimeoutSec   int            `json:"timeout_sec"`
	MaxFiles     int            `json:"max_files"`
	MaxProcesses int            `json:"max_processes"`
	NetworkBlock bool           `json:"network_block"`
	ReadonlyFS   bool           `json:"readonly_fs"`
	Rlimits      map[string]int `json:"rlimits"`
}

// AuditEntry represents an immutable audit log entry.
type AuditEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`  // "user", "agent", "system"
	Action     string    `json:"action"` // "check.run", "policy.change", "project.create"
	ResourceID string    `json:"resource_id"`
	Detail     string    `json:"detail"`
	Signature  string    `json:"signature,omitempty"` // HMAC over fields
}

// Policy defines declarative security rules.
type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	Rules     []Rule    `json:"rules"`
	Frozen    bool      `json:"frozen"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Rule is a single policy rule.
type Rule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // "block", "warn", "allow"
	Category    string `json:"category"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// NewDefaultSandboxConfig returns a restrictive sandbox configuration.
func NewDefaultSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		Namespace:    "qorvex-sandbox",
		User:         "nobody",
		MemoryMB:     512,
		CPUShares:    512,
		TimeoutSec:   60,
		MaxFiles:     128,
		MaxProcesses: 16,
		NetworkBlock: true,
		ReadonlyFS:   true,
		Rlimits: map[string]int{
			"NOFILE": 128,
			"NPROC":  16,
			"FSIZE":  10485760, // 10 MB max file size
		},
	}
}

// Clone returns a deep copy of the project.
func (p *Project) Clone() *Project {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

// Clone returns a deep copy of the check run, including its report and stages.
func (r *CheckRun) Clone() *CheckRun {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Stages = append([]Stage(nil), r.Stages...)
	if r.Result != nil {
		report := *r.Result
		report.Findings = append([]Finding(nil), r.Result.Findings...)
		if r.Result.SeverityCounts != nil {
			report.SeverityCounts = make(map[string]int, len(r.Result.SeverityCounts))
			for k, v := range r.Result.SeverityCounts {
				report.SeverityCounts[k] = v
			}
		}
		cp.Result = &report
	}
	return &cp
}

// Clone returns a copy of the finding.
func (f *Finding) Clone() *Finding {
	if f == nil {
		return nil
	}
	cp := *f
	return &cp
}

// Clone returns a copy of the audit entry.
func (a *AuditEntry) Clone() *AuditEntry {
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}
