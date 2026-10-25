package policy

import (
	"testing"

	"qorvex/pkg/platform"
)

func TestNewEngineHasDefault(t *testing.T) {
	e := NewEngine()
	policies, err := e.List()
	if err != nil {
		t.Errorf("list failed: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("expected 1 default policy, got %d", len(policies))
	}
}

func TestEvaluateAllAllowed(t *testing.T) {
	e := NewEngine()
	findings := []platform.Finding{
		{Severity: "info", Category: "quality", Description: "info info"},
	}
	result, _ := e.Evaluate(findings)
	if result.Allowed == 0 {
		t.Error("expected at least 1 allowed, got 0")
	}
	if !result.Passed {
		t.Error("should pass for info/quality")
	}
}

func TestSavePolicy(t *testing.T) {
	e := NewEngine()
	p := &platform.Policy{
		Name: "custom", Version: 1,
		Rules: []platform.Rule{
			{ID: "r1", Severity: "block", Category: "security", Pattern: ".*", Description: "block all security"},
		},
	}
	err := e.Save(p)
	if err != nil {
		t.Errorf("save failed: %v", err)
	}
	if p.ID == "" {
		t.Error("ID should be set after save")
	}
	got, _ := e.Get(p.ID)
	if got.Name != "custom" {
		t.Errorf("expected custom, got %s", got.Name)
	}
}

func TestGetPolicyNotFound(t *testing.T) {
	e := NewEngine()
	_, err := e.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent policy")
	}
}

func TestEvaluateBlockCritical(t *testing.T) {
	e := NewEngine()
	findings := []platform.Finding{
		{Severity: "critical", Category: "security", Description: "RCE"},
	}
	result, err := e.Evaluate(findings)
	if err != nil {
		t.Errorf("evaluate failed: %v", err)
	}
	if result.Passed {
		t.Error("should fail for critical security finding")
	}
	if result.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", result.Blocked)
	}
}

func TestEvaluateWarnQuality(t *testing.T) {
	e := NewEngine()
	findings := []platform.Finding{
		{Severity: "medium", Category: "quality", Description: "magic number"},
	}
	result, _ := e.Evaluate(findings)
	if result.Warned != 1 {
		t.Errorf("expected 1 warned, got %d", result.Warned)
	}
	if !result.Passed {
		t.Error("should pass for medium quality issue")
	}
}

func TestEvaluateBlockSecret(t *testing.T) {
	e := NewEngine()
	findings := []platform.Finding{
		{Severity: "high", Category: "secret", Description: "API key leak"},
	}
	result, _ := e.Evaluate(findings)
	if result.Blocked != 1 {
		t.Errorf("expected 1 blocked for secret, got %d", result.Blocked)
	}
}

func TestEvaluateMixedFindings(t *testing.T) {
	e := NewEngine()
	findings := []platform.Finding{
		{Severity: "critical", Category: "security", Description: "critical"},
		{Severity: "high", Category: "secret", Description: "secret"},
		{Severity: "medium", Category: "quality", Description: "medium"},
		{Severity: "low", Category: "quality", Description: "low"},
	}
	result, _ := e.Evaluate(findings)
	if result.Blocked != 2 {
		t.Errorf("expected 2 blocked, got %d", result.Blocked)
	}
	if result.Warned != 2 {
		t.Errorf("expected 2 warned, got %d", result.Warned)
	}
}

func TestEvaluateEmptyFindings(t *testing.T) {
	e := NewEngine()
	result, err := e.Evaluate(nil)
	if err != nil {
		t.Errorf("evaluate nil failed: %v", err)
	}
	if !result.Passed {
		t.Error("empty findings should pass")
	}
}

func TestListPolicies(t *testing.T) {
	e := NewEngine()
	policies, _ := e.List()
	count := len(policies)
	e.Save(&platform.Policy{Name: "p2"})
	policies, _ = e.List()
	if len(policies) != count+1 {
		t.Errorf("expected %d, got %d", count+1, len(policies))
	}
}

func TestDecisionStructure(t *testing.T) {
	e := NewEngine()
	result, _ := e.Evaluate([]platform.Finding{
		{Severity: "critical", Category: "security", Description: "test"},
	})
	if len(result.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(result.Decisions))
	}
	d := result.Decisions[0]
	if d.Verdict != "block" {
		t.Errorf("expected block, got %s", d.Verdict)
	}
	if d.Explanation == "" {
		t.Error("explanation should not be empty")
	}
}