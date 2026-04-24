package analyzer

import (
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// DependencyInventoryChecker flags MCP tools whose dependency inventory is not
// visible to the scanner, making supply-chain coverage incomplete.
type DependencyInventoryChecker struct{}

func NewDependencyInventoryChecker() *DependencyInventoryChecker {
	return &DependencyInventoryChecker{}
}

func (c *DependencyInventoryChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-014",
		Title:       "Dependency Inventory Unavailable",
		Description: "Flags MCP tools that do not expose dependency metadata or a repository URL, limiting supply-chain coverage.",
	}
}

func (c *DependencyInventoryChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	if tool.Protocol != model.ProtocolMCP {
		return nil, nil
	}

	if hasDependencyInventory(tool) {
		return nil, nil
	}

	note := "Tool did not expose metadata.dependencies or repo_url, so supply-chain coverage is limited."
	if tool.Metadata != nil {
		if n := metadataNote(tool.Metadata); n != "" {
			note = n
		}
	}

	return []model.Issue{{
		RuleID:      "AS-014",
		ToolName:    tool.Name,
		Severity:    model.SeverityInfo,
		Code:        "DEPENDENCY_INVENTORY_UNAVAILABLE",
		Description: note,
		Location:    "metadata",
		Evidence: []model.Evidence{
			{Kind: "dependency_visibility", Value: "none"},
		},
	}}, nil
}

func hasDependencyInventory(tool model.UnifiedTool) bool {
	if tool.Metadata == nil {
		return false
	}
	if repoURL := metadataString(tool.Metadata, "repo_url"); strings.TrimSpace(repoURL) != "" {
		return true
	}
	deps, err := extractDependencies(tool)
	return err == nil && len(deps) > 0
}

func metadataNote(meta map[string]any) string {
	if note, ok := meta["dependency_visibility_note"].(string); ok {
		return note
	}
	return ""
}
