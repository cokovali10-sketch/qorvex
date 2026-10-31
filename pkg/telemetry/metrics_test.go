package telemetry

import (
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector("proj-1", "chk-1")
	if c.data.ProjectID != "proj-1" {
		t.Errorf("expected proj-1")
	}
	if c.data.Status != "running" {
		t.Errorf("expected running")
	}
}

func TestRecordStage(t *testing.T) {
	c := NewCollector("p", "c")
	now := time.Now()
	c.RecordStage("scan", "completed", now, now.Add(time.Second), "", 5, map[string]int{"low": 5})
	if len(c.data.Stages) != 1 {
		t.Errorf("expected 1 stage")
	}
}

func TestFinalize(t *testing.T) {
	c := NewCollector("p", "c")
	c.Finalize("completed", 90, "low")
	if c.data.Status != "completed" {
		t.Errorf("expected completed")
	}
	if c.data.Score != 90 {
		t.Errorf("expected 90")
	}
}

func TestToJSON(t *testing.T) {
	c := NewCollector("p", "c")
	data, err := c.ToJSON()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty json")
	}
}

func TestReplayAudit(t *testing.T) {
	c := NewCollector("p", "c")
	now := time.Now()
	c.RecordStage("scan", "completed", now, now.Add(time.Second), "", 1, nil)
	replay := c.ReplayAudit()
	if len(replay) < 2 {
		t.Errorf("expected at least 2 entries")
	}
}

func TestMetrics(t *testing.T) {
	c := NewCollector("p", "c")
	now := time.Now()
	c.RecordStage("scan", "completed", now, now.Add(time.Second), "", 1, nil)
	m := c.Metrics()
	if m["stages_count"].(int) != 1 {
		t.Errorf("expected 1 stage")
	}
}

func TestValidate(t *testing.T) {
	c := NewCollector("p", "c")
	err := c.Validate()
	if err == nil {
		t.Error("expected error for no stages/finalized")
	}
	c.RecordStage("scan", "completed", time.Now(), time.Now(), "", 0, nil)
	c.Finalize("completed", 80, "low")
	if err := c.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}