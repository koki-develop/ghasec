package renderer

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

const (
	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

// SARIF 2.1.0 data structures (subset used by ghasec).

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	InformationURI string                     `json:"informationUri"`
	Version        string                     `json:"version,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifReportingDescriptor struct {
	ID               string        `json:"id"`
	HelpURI          string        `json:"helpUri,omitempty"`
	ShortDescription *sarifMessage `json:"shortDescription,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// SARIFRenderer outputs diagnostics as a single SARIF 2.1.0 JSON document.
// Results are buffered until PrintSummary flushes them to stdout.
type SARIFRenderer struct {
	driver  sarifDriver
	ruleMap map[string]int // ruleID → index in driver.Rules
	results []sarifResult
}

// NewSARIF creates a SARIFRenderer. ruleList provides active rules for the
// driver.rules array. version is included in the tool driver metadata.
func NewSARIF(ruleList []rules.Rule, version string) *SARIFRenderer {
	ruleMap := make(map[string]int)

	// Synthetic rules: parse-error at index 0, unused-ignore at index 1.
	descriptors := []sarifReportingDescriptor{
		{ID: "parse-error"},
		{
			ID:      "unused-ignore",
			HelpURI: "https://github.com/koki-develop/ghasec/blob/main/rules/unused-ignore/README.md",
		},
	}
	ruleMap["parse-error"] = 0
	ruleMap["unused-ignore"] = 1

	for i, r := range ruleList {
		idx := i + 2 // offset by 2 for synthetic entries at index 0 and 1
		desc := sarifReportingDescriptor{
			ID:      r.ID(),
			HelpURI: fmt.Sprintf("https://github.com/koki-develop/ghasec/blob/main/rules/%s/README.md", r.ID()),
		}
		if ex, ok := r.(rules.Explainer); ok {
			if why := ex.Why(); why != "" {
				desc.ShortDescription = &sarifMessage{Text: why}
			}
		}
		descriptors = append(descriptors, desc)
		ruleMap[r.ID()] = idx
	}

	return &SARIFRenderer{
		driver: sarifDriver{
			Name:           "ghasec",
			InformationURI: "https://github.com/koki-develop/ghasec",
			Version:        version,
			Rules:          descriptors,
		},
		ruleMap: ruleMap,
		results: []sarifResult{},
	}
}

// PrintParseError buffers a YAML parse error as a SARIF result.
func (r *SARIFRenderer) PrintParseError(path string, err error) error {
	yErr, ok := err.(yamlError)
	if !ok {
		return fmt.Errorf("unexpected parse error type for %s: %w", path, err)
	}
	tk := yErr.GetToken()
	if !isValidToken(tk) {
		return fmt.Errorf("parse error without position for %s: %s", path, yErr.GetMessage())
	}
	r.results = append(r.results, sarifResult{
		RuleID:    "parse-error",
		RuleIndex: 0,
		Level:     "error",
		Message:   sarifMessage{Text: yErr.GetMessage()},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: path},
				Region:           sarifRegion{StartLine: tk.Position.Line, StartColumn: tk.Position.Column},
			},
		}},
	})
	return nil
}

// PrintDiagnosticError buffers a diagnostic error as a SARIF result.
func (r *SARIFRenderer) PrintDiagnosticError(path string, e *diagnostic.Error) error {
	if !isValidToken(e.Token) {
		return fmt.Errorf("diagnostic error without position for %s: %s", path, e.Message)
	}
	ruleIndex := r.ruleMap[e.RuleID]
	r.results = append(r.results, sarifResult{
		RuleID:    e.RuleID,
		RuleIndex: ruleIndex,
		Level:     "error",
		Message:   sarifMessage{Text: e.Message},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: path},
				Region:           sarifRegion{StartLine: e.Token.Position.Line, StartColumn: e.Token.Position.Column},
			},
		}},
	})
	return nil
}

// PrintSummary marshals the buffered results as a SARIF JSON document to stdout.
func (r *SARIFRenderer) PrintSummary(totalFiles, errorCount, errorFileCount, skippedOnline int) error {
	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchemaURI,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: r.driver},
			Results: r.results,
		}},
	}
	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF output: %w", err)
	}
	_, writeErr := fmt.Fprintln(os.Stdout, string(out))
	return writeErr
}

// PrintHint is a no-op for the SARIF format.
func (r *SARIFRenderer) PrintHint(message string) error {
	return nil
}
