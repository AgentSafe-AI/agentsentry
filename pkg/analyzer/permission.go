package analyzer

import (
	"fmt"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

const largeSchemaPropThreshold = 10

// permissionRiskLevel maps each Permission to a base issue severity.
var permissionRiskLevel = map[model.Permission]model.Severity{
	model.PermissionExec:    model.SeverityHigh,
	model.PermissionNetwork: model.SeverityHigh,
	model.PermissionFS:      model.SeverityMedium,
	model.PermissionDB:      model.SeverityMedium,
	model.PermissionEnv:     model.SeverityMedium,
	model.PermissionHTTP:    model.SeverityLow,
}

// PermissionChecker analyses the declared permissions of a tool.
type PermissionChecker struct{}

func (c *PermissionChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-002",
		Title:       "Excessive Permission Surface",
		Description: "Flags tools requesting broad permissions such as shell execution, unrestricted file writes, or network access beyond their stated purpose.",
	}
}

// NewPermissionChecker returns a new PermissionChecker.
func NewPermissionChecker() *PermissionChecker { return &PermissionChecker{} }

// Check produces issues for each risky permission and for over-broad input schemas.
func (c *PermissionChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var issues []model.Issue

	for _, perm := range tool.Permissions {
		sev, known := permissionRiskLevel[perm]
		if !known {
			continue
		}
		issues = append(issues, model.Issue{
			RuleID:      "AS-002",
			ToolName:    tool.Name,
			Severity:    sev,
			Code:        "HIGH_RISK_PERMISSION",
			Description: fmt.Sprintf("tool declares %s permission", perm),
			Location:    "permissions",
			Evidence: []model.Evidence{
				{Kind: "permission", Value: string(perm)},
			},
		})
	}

	if propCount := tool.InputSchema.PropertyCount(); propCount > largeSchemaPropThreshold {
		issues = append(issues, model.Issue{
			RuleID:      "AS-002",
			ToolName:    tool.Name,
			Severity:    model.SeverityLow,
			Code:        "LARGE_INPUT_SURFACE",
			Description: fmt.Sprintf("input schema exposes %d properties (threshold: %d)", propCount, largeSchemaPropThreshold),
			Location:    "inputSchema",
			Evidence: []model.Evidence{
				{Kind: "schema_property_count", Value: fmt.Sprintf("%d", propCount)},
				{Kind: "schema_property_threshold", Value: fmt.Sprintf("%d", largeSchemaPropThreshold)},
			},
		})
	}

	return issues, nil
}
