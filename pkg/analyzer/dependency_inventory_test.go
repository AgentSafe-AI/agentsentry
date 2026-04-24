package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestDependencyInventoryChecker_MCPWithoutDependencies_Fires(t *testing.T) {
	checker := analyzer.NewDependencyInventoryChecker()
	tool := model.UnifiedTool{
		Name:     "safe_tool",
		Protocol: model.ProtocolMCP,
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-014", issues[0].RuleID)
	assert.Equal(t, model.SeverityInfo, issues[0].Severity)
	assert.Equal(t, "DEPENDENCY_INVENTORY_UNAVAILABLE", issues[0].Code)
}

func TestDependencyInventoryChecker_MCPWithDependencies_NoFinding(t *testing.T) {
	checker := analyzer.NewDependencyInventoryChecker()
	tool := model.UnifiedTool{
		Name:     "safe_tool",
		Protocol: model.ProtocolMCP,
		Metadata: map[string]any{
			"dependencies": []map[string]any{
				{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestDependencyInventoryChecker_MCPWithRepoURL_NoFinding(t *testing.T) {
	checker := analyzer.NewDependencyInventoryChecker()
	tool := model.UnifiedTool{
		Name:     "safe_tool",
		Protocol: model.ProtocolMCP,
		Metadata: map[string]any{
			"repo_url": "https://github.com/example/repo",
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestDependencyInventoryChecker_NonMCP_NoFinding(t *testing.T) {
	checker := analyzer.NewDependencyInventoryChecker()
	tool := model.UnifiedTool{
		Name:     "safe_tool",
		Protocol: model.ProtocolOpenAI,
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}
