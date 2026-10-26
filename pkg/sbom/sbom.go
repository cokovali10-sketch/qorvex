package sbom

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Component represents a single SBOM component (library, module, package).
type Component struct {
	Type     string `xml:"type,attr"`
	BOMRef   string `xml:"bom-ref,attr,omitempty"`
	Name     string `xml:"name"`
	Version  string `xml:"version,omitempty"`
	PURL     string `xml:"purl,omitempty"`
	Hash     string `xml:"hash,omitempty"`
	Licenses []License `xml:"licenses>license,omitempty"`
	Metadata map[string]string `xml:"-"`
}

// License represents a component license.
type License struct {
	Name string `xml:"name"`
	URL  string `xml:"url,omitempty"`
}

// Tool represents a tool used to generate the SBOM.
type Tool struct {
	Name    string `xml:"name"`
	Version string `xml:"version,omitempty"`
}

// Metadata is the SBOM metadata block.
type Metadata struct {
	Timestamp string `xml:"timestamp"`
	Tools     []Tool `xml:"tools>tool,omitempty"`
}

// Bom is the CycloneDX BOM document.
type Bom struct {
	XMLName     xml.Name `xml:"bom"`
	Xmlns       string   `xml:"xmlns,attr"`
	Version     string   `xml:"version,attr"`
	Serial      string   `xml:"serial,attr,omitempty"`
	Metadata    *Metadata `xml:"metadata,omitempty"`
	Components  []Component `xml:"components>component,omitempty"`
	Dependencies []Dependency `xml:"dependencies>dependency,omitempty"`
}

// Dependency represents a dependency relationship between components.
type Dependency struct {
	Ref       string   `xml:"ref,attr"`
	DependsOn []string `xml:"dependency>ref,attr,omitempty"`
}

// Generator builds CycloneDX SBOMs.
type Generator struct {
	ToolName    string
	ToolVersion string
	Project     string
	Version     string
}

func NewGenerator(project, version string) *Generator {
	return &Generator{
		ToolName:    "qorvex",
		ToolVersion: "0.3.0",
		Project:     project,
		Version:     version,
	}
}

// ComponentFromScan turns a scanner finding list into lightweight components.
func (g *Generator) ComponentFromScan(components []map[string]string) []Component {
	out := make([]Component, 0, len(components))
	for _, c := range components {
		out = append(out, Component{
			Type:    "library",
			Name:    c["name"],
			Version: c["version"],
			PURL:    c["purl"],
			Hash:    c["hash"],
			Licenses: func() []License {
				if c["license"] == "" {
					return nil
				}
				return []License{{Name: c["license"]}}
			}(),
			Metadata: c,
		})
	}
	return out
}

// Generate builds the CycloneDX XML BOM.
func (g *Generator) Generate(components []Component) (*Bom, error) {
	dedup := map[string]bool{}
	uniq := make([]Component, 0, len(components))
	for _, c := range components {
		key := c.Name + "|" + c.Version
		if dedup[key] {
			continue
		}
		dedup[key] = true
		uniq = append(uniq, c)
	}

	bom := &Bom{
		Xmlns:   "http://cyclonedx.org/schema/bom/1.2",
		Version: "1",
		Serial:  fmt.Sprintf("urn:uuid:%s", g.Project),
		Metadata: &Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{Name: g.ToolName, Version: g.ToolVersion},
			},
		},
		Components: uniq,
	}
	return bom, nil
}

// MarshalXML writes the BOM as CycloneDX XML.
func (b *Bom) MarshalXML() ([]byte, error) {
	return xml.MarshalIndent(b, "", "  ")
}

// String returns a compact text summary of the BOM.
func (b *Bom) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SBOM: %d component(s)\n", len(b.Components)))
	for _, c := range b.Components {
		sb.WriteString(fmt.Sprintf("  - %s %s (%s)\n", c.Name, c.Version, c.PURL))
	}
	return sb.String()
}
