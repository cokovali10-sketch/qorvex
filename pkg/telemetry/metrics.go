// Qorvex Pipeline Telemetry v0.3.0
// Metrics collection, stage timing, failure classification, telemetry replay.
package telemetry

import (
	"encoding/json"
	"fmt"
	"time"
)

// MetricType defines telemetry metric categories.
type MetricType string

const (
	MetricStageDuration MetricType = "stage_duration_ms"
	MetricStageStatus   MetricType = "stage_status"
	MetricFindingsCount MetricType = "findings_count"
	MetricFindingSeverity MetricType = "finding_severity"
	MetricAuditEvent    MetricType = "audit_event"
	MetricPipelineStart  MetricType = "pipeline_start"
	MetricPipelineEnd    MetricType = "pipeline_end"
	MetricPipelineFailed MetricType = "pipeline_failed"
)

// StageTelemetry captures timing and outcome for a single pipeline stage.
type StageTelemetry struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"` // completed | failed | skipped
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	DurationMs    int64     `json:"duration_ms"`
	Error         string    `json:"error,omitempty"`
	FindingsCount int       `json:"findings_count"`
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
}

// PipelineTelemetry aggregates all stage data.
type PipelineTelemetry struct {
	ProjectID     string            `json:"project_id"`
	CheckID       string            `json:"check_id"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at,omitempty"`
	Status        string            `json:"status"` // running | completed | failed
	RiskLevel     string            `json:"risk_level,omitempty"`
	Score         int               `json:"score,omitempty"`
	Stages        []StageTelemetry `json:"stages"`
	TotalDurationMs int64          `json:"total_duration_ms"`
	AuditReplayEnabled bool         `json:"audit_replay_enabled"`
}

// Collector manages telemetry accumulation.
type Collector struct {
	data PipelineTelemetry
}

// NewCollector creates telemetry for a pipeline run.
func NewCollector(projectID, checkID string) *Collector {
	return &Collector{
		data: PipelineTelemetry{
			ProjectID: projectID,
			CheckID:   checkID,
			StartedAt: time.Now().UTC(),
			Status:    "running",
			Stages:    make([]StageTelemetry, 0, 9),
		},
	}
}

// RecordStage logs a completed pipeline stage.
func (c *Collector) RecordStage(name string, status string, start, end time.Time, errMsg string, findings int, counts map[string]int) {
	dur := end.Sub(start).Milliseconds()
	stage := StageTelemetry{
		Name:       name,
		Status:     status,
		StartTime:  start.UTC(),
		EndTime:    end.UTC(),
		DurationMs: dur,
		Error:      errMsg,
		FindingsCount: findings,
		SeverityCounts: counts,
	}
	c.data.Stages = append(c.data.Stages, stage)
}

// Finalize completes pipeline telemetry.
func (c *Collector) Finalize(status string, score int, risk string) {
	c.data.Status = status
	c.data.CompletedAt = time.Now().UTC()
	c.data.TotalDurationMs = time.Since(c.data.StartedAt).Milliseconds()
	c.data.Score = score
	c.data.RiskLevel = risk
	if status == "failed" && risk == "critical" {
		c.data.AuditReplayEnabled = true // trigger replay
	}
}

// ToJSON serializes telemetry.
func (c *Collector) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c.data, "", "  ")
}

// ReplayAudit rebuilds audit trail from telemetry (useful for verification).
func (c *Collector) ReplayAudit() []map[string]interface{} {
	replay := make([]map[string]interface{}, 0, len(c.data.Stages)+2)
	replay = append(replay, map[string]interface{}{
		"action":    "pipeline_start",
		"project_id": c.data.ProjectID,
		"check_id":  c.data.CheckID,
		"timestamp": c.data.StartedAt.Format(time.RFC3339),
	})
	for _, s := range c.data.Stages {
		replay = append(replay, map[string]interface{}{
			"action":     s.Name,
			"status":     s.Status,
			"duration_ms": s.DurationMs,
			"error":      s.Error,
			"findings":   s.FindingsCount,
			"timestamp":  s.EndTime.Format(time.RFC3339),
		})
	}
	replay = append(replay, map[string]interface{}{
		"action":     "pipeline_end",
		"status":     c.data.Status,
		"risk_level": c.data.RiskLevel,
		"timestamp":  c.data.CompletedAt.Format(time.RFC3339),
	})
	return replay
}

// Metrics exposes key performance indicators.
func (c *Collector) Metrics() map[string]interface{} {
	total := int64(0)
	failed := 0
	for _, s := range c.data.Stages {
		total += s.DurationMs
		if s.Status == "failed" {
			failed++
		}
	}
	return map[string]interface{}{
		"project_id":        c.data.ProjectID,
		"total_duration_ms": total,
		"stages_count":      len(c.data.Stages),
		"failed_stages":     failed,
		"status":            c.data.Status,
		"risk_level":        c.data.RiskLevel,
	}
}

// Validate checks telemetry consistency.
func (c *Collector) Validate() error {
	if c.data.CheckID == "" {
		return fmt.Errorf("telemetry missing check_id")
	}
	if len(c.data.Stages) == 0 {
		return fmt.Errorf("telemetry has no stages")
	}
	if c.data.Status == "running" && c.data.CompletedAt.IsZero() {
		return fmt.Errorf("telemetry running but not finalized")
	}
	return nil
}
