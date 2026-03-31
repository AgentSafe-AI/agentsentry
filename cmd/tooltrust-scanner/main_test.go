package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestCheckFailOn_Empty(t *testing.T) {
	err := checkFailOn("", ScanSummary{Blocked: 5})
	assert.NoError(t, err)
}

func TestCheckFailOn_BlockWithBlocked(t *testing.T) {
	err := checkFailOn("block", ScanSummary{Total: 3, Blocked: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BLOCKED")
}

func TestCheckFailOn_BlockWithNoneBlocked(t *testing.T) {
	err := checkFailOn("block", ScanSummary{Total: 3, Allowed: 2, RequireApproval: 1})
	assert.NoError(t, err)
}

func TestCheckFailOn_ApprovalTriggered(t *testing.T) {
	err := checkFailOn("approval", ScanSummary{Total: 3, RequireApproval: 2, Allowed: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "require approval")
}

func TestCheckFailOn_ApprovalNotTriggered(t *testing.T) {
	err := checkFailOn("approval", ScanSummary{Total: 3, Allowed: 3})
	assert.NoError(t, err)
}

func TestCheckFailOn_AllowTriggered(t *testing.T) {
	err := checkFailOn("allow", ScanSummary{Total: 3, Allowed: 1, RequireApproval: 2})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "allowed")
}

func TestCheckFailOn_AllowNotTriggered(t *testing.T) {
	err := checkFailOn("allow", ScanSummary{Total: 3, Allowed: 3})
	assert.NoError(t, err)
}

func TestCheckFailOn_InvalidValue(t *testing.T) {
	err := checkFailOn("bogus", ScanSummary{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --fail-on")
}

func TestFormatToolLabel_HidesScoreForAllowGradeA(t *testing.T) {
	label := formatToolLabel(model.GatewayPolicy{
		ToolName: "read_file",
		Action:   model.ActionAllow,
		Score: model.RiskScore{
			Score: 8,
			Grade: model.GradeA,
		},
	})

	assert.Contains(t, label, "[ALLOW]")
	assert.NotContains(t, label, "score=8")
	assert.NotContains(t, label, "grade=A")
}

func TestFormatToolLabel_KeepsGradeForApproval(t *testing.T) {
	label := formatToolLabel(model.GatewayPolicy{
		ToolName: "search_files",
		Action:   model.ActionRequireApproval,
		Score: model.RiskScore{
			Score: 25,
			Grade: model.GradeC,
		},
	})

	assert.Contains(t, label, "[APPROVAL]")
	assert.Contains(t, label, "grade=C")
	assert.NotContains(t, label, "score=25")
}

func TestFormatIssueLabel_HidesRedundantEvidenceForAllowGradeA(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityMedium,
		Description: "tool declares fs permission",
		Evidence: []model.Evidence{
			{Kind: "permission", Value: "fs"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionAllow,
		Score:  model.RiskScore{Grade: model.GradeA},
	}, true)

	assert.Contains(t, label, "• [AS-002] MEDIUM:")
	assert.NotContains(t, label, "(+8)")
	assert.NotContains(t, label, "Evidence:")
	assert.NotContains(t, label, "Tool requests broad permissions")
}

func TestFormatIssueLabel_HidesRedundantSingleEvidenceForFlaggedTools(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityHigh,
		Description: "tool declares network permission",
		Evidence: []model.Evidence{
			{Kind: "permission", Value: "network"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, true)

	assert.Contains(t, label, "• [AS-002] HIGH:")
	assert.NotContains(t, label, "Evidence:")
	assert.Contains(t, label, "Tool requests broad permissions")
}

func TestFormatIssueLabel_KeepsCompactEvidenceForNonRedundantFlaggedTools(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityHigh,
		Description: "tool declares network permission",
		Evidence: []model.Evidence{
			{Kind: "permission", Value: "network"},
			{Kind: "schema_property_count", Value: "12"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, true)

	assert.Contains(t, label, "Evidence: permission=network")
	assert.Contains(t, label, "… 1 more evidence item(s)")
	assert.NotContains(t, label, "schema_property_count=12")
}

func TestFormatIssueLabel_HidesHintWhenAlreadyShownForRule(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityHigh,
		Description: "tool declares network permission",
		Evidence: []model.Evidence{
			{Kind: "permission", Value: "network"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, false)

	assert.Contains(t, label, "• [AS-002] HIGH:")
	assert.NotContains(t, label, "Tool requests broad permissions")
}

func TestSummarizeToolReason_EmptyForAllow(t *testing.T) {
	reason := summarizeToolReason(model.GatewayPolicy{
		Action: model.ActionAllow,
		Score: model.RiskScore{
			Grade: model.GradeA,
			Issues: []model.Issue{
				{
					RuleID:      "AS-002",
					Description: "tool declares fs permission",
					Evidence:    []model.Evidence{{Kind: "permission", Value: "fs"}},
				},
			},
		},
	})

	assert.Equal(t, "", reason)
}

func TestSummarizeToolReason_ForApproval(t *testing.T) {
	reason := summarizeToolReason(model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score: model.RiskScore{
			Grade: model.GradeC,
			Issues: []model.Issue{
				{
					RuleID:      "AS-002",
					Description: "tool declares fs permission",
					Evidence:    []model.Evidence{{Kind: "permission", Value: "fs"}},
				},
				{
					RuleID:      "AS-002",
					Description: "tool declares network permission",
					Evidence:    []model.Evidence{{Kind: "permission", Value: "network"}},
				},
				{
					RuleID:      "AS-011",
					Description: "tool performs network or execution operations but declares no rate-limit, timeout, or retry configuration",
				},
			},
		},
	})

	assert.Equal(t, "fs permission + network permission + missing rate-limit/timeout", reason)
}

func TestToolReasonLabel_ForApproval(t *testing.T) {
	assert.Equal(t, "Why approval: ", toolReasonLabel(model.GatewayPolicy{Action: model.ActionRequireApproval}))
}

func TestToolReasonLabel_ForBlock(t *testing.T) {
	assert.Equal(t, "Why blocked: ", toolReasonLabel(model.GatewayPolicy{Action: model.ActionBlock}))
}
