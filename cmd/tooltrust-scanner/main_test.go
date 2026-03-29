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

func TestFormatIssueLabel_IncludesCompactEvidence(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityHigh,
		Description: "tool declares network permission",
		Evidence: []model.Evidence{
			{Kind: "permission", Value: "network"},
			{Kind: "schema_property_count", Value: "12"},
		},
	})

	assert.Contains(t, label, "Evidence: permission=network")
	assert.Contains(t, label, "… 1 more evidence item(s)")
	assert.NotContains(t, label, "schema_property_count=12")
}
