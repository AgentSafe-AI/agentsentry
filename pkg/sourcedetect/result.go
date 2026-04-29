package sourcedetect

import "github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"

type Options struct {
	MaxFiles              int
	MaxFileSizeBytes      int64
	MaxMatchesPerLanguage int
}

type DetectionResult struct {
	SchemaVersion  string           `json:"schema_version"`
	Mode           string           `json:"mode"`
	HasEmbeddedMCP bool             `json:"has_embedded_mcp"`
	Detection      DetectionSummary `json:"detection"`
	Findings       []model.Issue    `json:"findings,omitempty"`
}

type DetectionSummary struct {
	Matches       []Match        `json:"matches,omitempty"`
	RouteFindings []RouteFinding `json:"route_findings,omitempty"`
	FilesScanned  int            `json:"files_scanned"`
	Elapsed       string         `json:"elapsed"`
}

type Match struct {
	Language string     `json:"language"`
	File     string     `json:"file"`
	Evidence []Evidence `json:"evidence"`
}

type Evidence struct {
	Kind    string `json:"kind"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type RouteFinding struct {
	Language         string     `json:"language"`
	File             string     `json:"file"`
	Authenticated    RouteMatch `json:"authenticated"`
	Unauthenticated  RouteMatch `json:"unauthenticated"`
	FailOpenEvidence *Evidence  `json:"fail_open_evidence,omitempty"`
}

type RouteMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Handler string `json:"handler"`
}

func defaultOptions() Options {
	return Options{
		MaxFiles:              5000,
		MaxFileSizeBytes:      1 << 20, // 1 MiB
		MaxMatchesPerLanguage: 3,
	}
}
