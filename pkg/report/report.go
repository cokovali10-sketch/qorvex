package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"qorvex/pkg/platform"
)

// Format exports a check run report in the requested format:
// "json", "sarif", or "html".
func Format(format string, run *platform.CheckRun) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return ExportJSON(run)
	case "sarif":
		return ExportSARIF(run)
	case "html":
		return ExportHTML(run)
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// ExportJSON returns the report as JSON.
func ExportJSON(run *platform.CheckRun) ([]byte, error) {
	return json.MarshalIndent(run, "", "  ")
}

// sarifRun is the top-level SARIF document.
type sarifRun struct {
	Version   string     `json:"version"`
	Schema    string     `json:"$schema"`
	Runs      []sarifRunData `json:"runs"`
}

type sarifRunData struct {
	Tool      sarifTool      `json:"tool"`
	Results   []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Rules   []sarifRule    `json:"rules,omitempty"`
}

type sarifRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	ShortDesc   sarifMessage   `json:"shortDescription"`
	FullDesc    sarifMessage   `json:"fullDescription,omitempty"`
	Help        sarifMessage   `json:"help,omitempty"`
	Properties  sarifProperties `json:"properties,omitempty"`
}

type sarifProperties struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
	Precision        string `json:"precision,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	RuleIndex int            `json:"ruleIndex"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// ExportSARIF returns the report as a SARIF 2.1.0 document.
func ExportSARIF(run *platform.CheckRun) ([]byte, error) {
	ruleIndex := map[string]int{}
	rules := []sarifRule{}
	results := []sarifResult{}

	for _, f := range run.Result.Findings {
		idx, ok := ruleIndex[f.RuleID]
		level := sarifLevel(f.Severity)
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, sarifRule{
				ID:          f.RuleID,
				Name:        f.Category,
				ShortDesc:   sarifMessage{Text: f.Description},
				FullDesc:    sarifMessage{Text: f.Description},
				Properties:  sarifProperties{SecuritySeverity: sarifSeverity(f.Severity)},
			})
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     level,
			Message:   sarifMessage{Text: f.Description},
			Locations: sarifLocations(f),
		})
	}

	doc := sarifRun{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
		Runs: []sarifRunData{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "qorvex",
						Version: "0.3.0",
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

func sarifSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "0.0"
	}
}

func sarifLocations(f platform.Finding) []sarifLocation {
	if f.FilePath == "" {
		return nil
	}
	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifact{URI: f.FilePath},
		},
	}
	if f.LineStart > 0 {
		loc.PhysicalLocation.Region = sarifRegion{StartLine: f.LineStart}
	}
	return []sarifLocation{loc}
}

// ExportHTML returns the report as a self-contained HTML page.
func ExportHTML(run *platform.CheckRun) ([]byte, error) {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Qorvex Report " + html.EscapeString(run.ID) + "</title>")
	b.WriteString("<style>body{font-family:system-ui,sans-serif;padding:24px;color:#111}table{border-collapse:collapse;width:100%;margin-top:12px}th,td{border:1px solid #ccc;padding:6px;text-align:left}th{background:#f4f4f4}.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;color:#fff}.critical{background:#b00020}.high{background:#e64a19}.medium{background:#f9a825}.low{background:#43a047}.info{background:#1e88e5}.h1{font-size:24px;margin-bottom:8px}.meta{color:#666;margin-bottom:16px}</style>")
	b.WriteString("</head><body>")
	b.WriteString("<h1 class='h1'>Qorvex — отчёт проверки</h1>")
	b.WriteString("<div class='meta'><strong>Проверка:</strong> " + html.EscapeString(run.ID) + " &nbsp;|&nbsp; <strong>Статус:</strong> " + html.EscapeString(run.Status) + " &nbsp;|&nbsp; <strong>Счёт:</strong> " + fmt.Sprintf("%.1f", run.Result.Score) + " &nbsp;|&nbsp; <strong>Риск:</strong> " + html.EscapeString(run.Result.RiskLevel) + "</div>")
	b.WriteString("<table><thead><tr><th>Серьёзность</th><th>Категория</th><th>Описание</th><th>Файл</th><th>Строка</th><th>CWE</th><th>Правило</th></tr></thead><tbody>")
	for _, f := range run.Result.Findings {
		b.WriteString("<tr>")
		b.WriteString("<td><span class='badge " + html.EscapeString(strings.ToLower(f.Severity)) + "'>" + html.EscapeString(f.Severity) + "</span></td>")
		b.WriteString("<td>" + html.EscapeString(f.Category) + "</td>")
		b.WriteString("<td>" + html.EscapeString(f.Description) + "</td>")
		b.WriteString("<td class='mono'>" + html.EscapeString(f.FilePath) + "</td>")
		b.WriteString("<td>" + fmt.Sprintf("%d", f.LineStart) + "</td>")
		b.WriteString("<td>" + html.EscapeString(f.CWE) + "</td>")
		b.WriteString("<td>" + html.EscapeString(f.RuleID) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table>")
	b.WriteString("<p><strong>Итого:</strong> " + fmt.Sprintf("%d", len(run.Result.Findings)) + " заключений &nbsp;|&nbsp; <strong>Сводка:</strong> " + html.EscapeString(run.Result.Summary) + "</p>")
	b.WriteString("</body></html>")
	return []byte(b.String()), nil
}
