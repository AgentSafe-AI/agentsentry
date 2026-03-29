package model

// Severity indicates how critical an individual issue is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Grade is the overall letter-grade assigned to a tool's risk score.
type Grade string

const (
	GradeA Grade = "A" // 0–10:  no significant risk
	GradeB Grade = "B" // 11–25: low risk, recommend monitoring
	GradeC Grade = "C" // 26–50: medium risk, review required
	GradeD Grade = "D" // 51–75: high risk, manual authorisation needed
	GradeF Grade = "F" // 76+:   critical risk, block immediately
)

// GradeFromScore maps a numeric score to a Grade letter.
// Boundaries align with the ToolTrust Directory methodology v1.0:
// A:0–9  B:10–24  C:25–49  D:50–74  F:75+.
func GradeFromScore(score int) Grade {
	switch {
	case score <= 9:
		return GradeA
	case score <= 24:
		return GradeB
	case score <= 49:
		return GradeC
	case score <= 74:
		return GradeD
	default:
		return GradeF
	}
}

// Issue describes a single risk finding detected during analysis.
type Evidence struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Issue struct {
	RuleID      string     `json:"rule_id"` // unique rule identifier, e.g. "AS-001"
	Severity    Severity   `json:"severity"`
	Code        string     `json:"code"` // e.g. "TOOL_POISONING", "SCOPE_MISMATCH"
	Description string     `json:"description,omitempty"`
	Location    string     `json:"location,omitempty"`
	ToolName    string     `json:"tool_name,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
}

// RiskScore is the aggregated result of running all analyzers on a UnifiedTool.
type RiskScore struct {
	Score  int     `json:"risk_score"`
	Grade  Grade   `json:"grade"`
	Issues []Issue `json:"findings"`
}

// NewRiskScore constructs a RiskScore, automatically deriving the Grade.
func NewRiskScore(score int, issues []Issue) RiskScore {
	return RiskScore{
		Score:  score,
		Grade:  GradeFromScore(score),
		Issues: issues,
	}
}

// IsClean returns true when the score is zero and no issues were found.
func (r RiskScore) IsClean() bool {
	return r.Score == 0 && len(r.Issues) == 0
}
