package policy

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"qorvex/pkg/platform"
)

// Engine evaluates declarative policies against findings.
type Engine struct {
	mu       sync.RWMutex
	policies map[string]*platform.Policy
	counter  atomic.Int64
}

func NewEngine() *Engine {
	e := &Engine{policies: make(map[string]*platform.Policy)}
	_ = e.Save(&platform.Policy{
		Name:    "default",
		Version: 1,
		Frozen:  true,
		Rules: []platform.Rule{
			{ID: "block-critical", Severity: "block", Category: "security", Pattern: "critical", Description: "Block critical findings"},
			{ID: "block-secrets", Severity: "block", Category: "secret", Pattern: ".*", Description: "Block any secret leakage"},
			{ID: "warn-deps", Severity: "warn", Category: "dependency", Pattern: "high|critical", Description: "Warn on high/critical deps"},
			{ID: "warn-quality", Severity: "warn", Category: "quality", Pattern: "medium|low", Description: "Warn on quality issues"},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	return e
}

func (e *Engine) Save(p *platform.Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.ID == "" {
		p.ID = fmt.Sprintf("pol-%d-%d", time.Now().UnixMilli(), e.counter.Add(1))
	}
	p.UpdatedAt = time.Now()
	e.policies[p.ID] = p
	return nil
}

func (e *Engine) Get(id string) (*platform.Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return p, nil
}

func (e *Engine) List() ([]*platform.Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	res := make([]*platform.Policy, 0, len(e.policies))
	for _, p := range e.policies {
		res = append(res, p)
	}
	return res, nil
}

// Evaluate applies policies to a set of findings and returns decisions.
func (e *Engine) Evaluate(findings []platform.Finding) (*Result, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := &Result{
		Decisions: make([]Decision, 0, len(findings)),
	}

	for _, f := range findings {
		decision := Decision{
			Finding:     f,
			Verdict:     "allow",
			Explanation: "no matching rule",
		}

		for _, p := range e.policies {
			for _, r := range p.Rules {
				if !(r.Category == f.Category || r.Category == "any") {
					continue
				}

				// Pattern matching: | for OR logic
				matched := false
				parts := strings.Split(strings.TrimSpace(r.Pattern), "|")
				for _, part := range parts {
					p := strings.TrimSpace(part)
					if p == ".*" || strings.Contains(f.Severity, p) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}

				var override bool
				switch r.Severity {
				case "block":
					decision.Verdict = "block"
					decision.Explanation = r.Description
					override = true
				case "warn":
					if decision.Verdict == "allow" {
						decision.Verdict = "warn"
						decision.Explanation = r.Description
						override = true
					}
				case "allow":
					// Allow rules only apply when no block rule has matched
					if decision.Verdict == "allow" {
						decision.Explanation = "explicitly allowed by policy"
						override = true
					}
				}
				if override {
					decision.RuleID = r.ID
					decision.PolicyID = p.ID
				}
			}
		}

		res.Decisions = append(res.Decisions, decision)
	}

	// Summarize
	blocked := 0
	warned := 0
	allowed := 0
	for _, d := range res.Decisions {
		switch d.Verdict {
		case "block":
			blocked++
		case "warn":
			warned++
		default:
			allowed++
		}
	}
	res.Blocked = blocked
	res.Warned = warned
	res.Allowed = allowed
	res.Passed = blocked == 0
	res.Summary = fmt.Sprintf("%d allowed, %d warned, %d blocked", allowed, warned, blocked)

	return res, nil
}

// Result of policy evaluation.
type Result struct {
	Decisions []Decision `json:"decisions"`
	Passed    bool       `json:"passed"`
	Blocked   int        `json:"blocked"`
	Warned    int        `json:"warned"`
	Allowed   int        `json:"allowed"`
	Summary   string     `json:"summary"`
}

// Decision for a single finding.
type Decision struct {
	Finding     platform.Finding `json:"finding"`
	Verdict     string           `json:"verdict"`
	Explanation string           `json:"explanation"`
	RuleID      string           `json:"rule_id"`
	PolicyID    string           `json:"policy_id"`
}

// Merge allows manual overrides of policy verdicts.
func (e *Engine) Merge(decisions []Decision) ([]Decision, error) {
	res := make([]Decision, len(decisions))
	copy(res, decisions)
	return res, nil
}
