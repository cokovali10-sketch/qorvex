package report

import (
	"strings"
	"testing"

	"qorvex/pkg/platform"
)

func testRun() *platform.CheckRun {
	return &platform.CheckRun{
		ID:     "chk-1",
		Status: "completed",
		Result: &platform.Report{
			ID:          "rep-1",
			CheckRunID:  "chk-1",
			Score:       72.5,
			RiskLevel:   "medium",
			SeverityCounts: map[string]int{"high": 1, "medium": 2, "low": 3},
			Findings: []platform.Finding{
				{
					ID:          "f-1",
					ProjectID:   "proj-1",
					CheckRunID:  "chk-1",
					Severity:    "high",
					Category:    "security",
					Description: "hardcoded password",
					FilePath:    "src/app.go",
					LineStart:   42,
					CWE:         "CWE-798",
					RuleID:      "secret-hardcoded",
				},
				{
					ID:          "f-2",
					ProjectID:   "proj-1",
					CheckRunID:  "chk-1",
					Severity:    "low",
					Category:    "quality",
					Description: "unused import",
					FilePath:    "src/app.go",
					LineStart:   5,
					RuleID:      "quality-unused",
				},
			},
			Summary: "Score 72.5/100; risk medium; 3 finding(s): 0 critical, 1 high, 2 medium, 3 low",
		},
	}
}

func TestExportJSON(t *testing.T) {
	data, err := ExportJSON(testRun())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "risk_level") {
		t.Fatal("risk_level missing in JSON")
	}
	if !strings.Contains(s, "hardcoded password") {
		t.Fatal("finding missing in JSON")
	}
	if !strings.Contains(s, "unused import") {
		t.Fatal("second finding missing in JSON")
	}
}

func TestExportSARIF(t *testing.T) {
	data, err := ExportSARIF(testRun())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "$schema") {
		t.Fatal("sarif schema missing")
	}
	if !strings.Contains(s, "secret-hardcoded") {
		t.Fatal("sarif rule missing")
	}
	if !strings.Contains(s, "src/app.go") {
		t.Fatal("sarif artifact missing")
	}
	if !strings.Contains(s, "error") {
		t.Fatal("sarif high severity should be error")
	}
}

func TestExportHTML(t *testing.T) {
	data, err := ExportHTML(testRun())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "hardcoded password") {
		t.Fatal("finding missing in HTML")
	}
	if !strings.Contains(s, "CWE-798") {
		t.Fatal("cwe missing in HTML")
	}
	if !strings.Contains(s, "72.5") {
		t.Fatal("score missing in HTML")
	}
}

func TestFormatDispatch(t *testing.T) {
	for _, f := range []string{"json", "sarif", "html"} {
		if _, err := Format(f, testRun()); err != nil {
			t.Fatalf("format %s failed: %v", f, err)
		}
	}
	if _, err := Format("yaml", testRun()); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}
