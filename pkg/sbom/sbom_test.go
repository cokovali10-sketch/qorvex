package sbom

import (
	"strings"
	"testing"
)

func TestGenerateBom(t *testing.T) {
	g := NewGenerator("demo-project", "1.0.0")

	comps := g.ComponentFromScan([]map[string]string{
		{"name": "github.com/foo/bar", "version": "v1.2.3", "purl": "pkg:golang/github.com/foo/bar@v1.2.3", "license": "MIT"},
		{"name": "github.com/foo/bar", "version": "v1.2.3", "purl": "pkg:golang/github.com/foo/bar@v1.2.3", "license": "MIT"},
		{"name": "npm:lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "license": "MIT"},
	})

	bom, err := g.Generate(comps)
	if err != nil {
		t.Fatal(err)
	}

	if len(bom.Components) != 2 {
		t.Fatalf("expected 2 deduped components, got %d", len(bom.Components))
	}
	if bom.Metadata == nil || bom.Metadata.Timestamp == "" {
		t.Fatal("metadata timestamp missing")
	}
	if bom.Components[0].Licenses == nil || bom.Components[0].Licenses[0].Name != "MIT" {
		t.Fatal("license not carried over")
	}

	xmlOut, err := bom.ToXML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xmlOut), "cyclonedx.org") {
		t.Fatal("missing cyclonedx namespace")
	}
	if !strings.Contains(string(xmlOut), "github.com/foo/bar") {
		t.Fatal("component missing in XML")
	}

	s := bom.String()
	if !strings.Contains(s, "npm:lodash") {
		t.Fatal("summary missing component")
	}
}

func TestGeneratorMetadata(t *testing.T) {
	g := NewGenerator("p", "1")
	if g.ToolName != "qorvex" {
		t.Fatal("tool name wrong")
	}
}
