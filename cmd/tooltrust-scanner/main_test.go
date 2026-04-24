package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
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

func TestFormatIssueLabel_ShowsHintForNPMLifecycleScripts(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-015",
		Severity:    model.SeverityMedium,
		Description: "npm package axios@1.14.1 publishes a postinstall lifecycle script (node install.js). Review whether this install-time execution is expected.",
		Evidence: []model.Evidence{
			{Kind: "package", Value: "axios"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, true)

	assert.Contains(t, label, "• [AS-015] MEDIUM:")
	assert.Contains(t, label, "Review the install-time script before use")
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

func TestDependencyVisibilityForTool_None(t *testing.T) {
	visibility, note := analyzer.DependencyVisibilityForTool(model.UnifiedTool{
		Name: "plain_tool",
	})

	assert.Equal(t, "No dependency data", visibility)
	assert.Contains(t, note, "No metadata.dependencies or repo_url")
}

func TestDependencyVisibilityForTool_MetadataAndRepoURL(t *testing.T) {
	visibility, note := analyzer.DependencyVisibilityForTool(model.UnifiedTool{
		Name: "tool",
		Metadata: map[string]any{
			"repo_url": "https://github.com/example/repo",
			"dependencies": []map[string]any{
				{"name": "axios", "version": "1.14.1", "ecosystem": "npm", "source": "local_lockfile"},
			},
		},
	})

	assert.Equal(t, "Verified from local lockfile + Repo URL available", visibility)
	assert.Empty(t, note)
}

func TestToolContextLines_EmptyForAllowGradeA(t *testing.T) {
	lines := toolContextLines(model.GatewayPolicy{
		Action: model.ActionAllow,
		Score:  model.RiskScore{Grade: model.GradeA},
		Behavior: []string{
			"reads_files",
		},
		Destinations: []string{
			"dynamic URL input (url)",
		},
	})

	assert.Nil(t, lines)
}

func TestToolContextLines_ForFlaggedTool(t *testing.T) {
	lines := toolContextLines(model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
		Behavior: []string{
			"reads_files",
			"uses_network",
		},
		Destinations: []string{
			"dynamic URL input (url)",
			"hardcoded domain: api.postmarkapp.com",
		},
	})

	assert.Equal(t, []string{
		"Behavior: reads_files, uses_network",
		"Destination: dynamic URL input (url); hardcoded domain: api.postmarkapp.com",
	}, lines)
}

func TestDependencyVisibilityLines_HiddenForAllowGradeAWithoutCoverage(t *testing.T) {
	line, note := dependencyVisibilityLines(model.GatewayPolicy{
		Action:               model.ActionAllow,
		Score:                model.RiskScore{Grade: model.GradeA},
		DependencyVisibility: "No dependency data",
		DependencyNote:       "No metadata.dependencies or repo_url were exposed by this MCP server.",
	})

	assert.Equal(t, "", line)
	assert.Equal(t, "", note)
}

func TestFormatIssueLabel_HidesAS014NoiseForAllowGradeA(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-014",
		Severity:    model.SeverityInfo,
		Description: "Tool did not expose metadata.dependencies or repo_url, so supply-chain coverage is limited.",
		Evidence: []model.Evidence{
			{Kind: "dependency_visibility", Value: "none"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionAllow,
		Score:  model.RiskScore{Grade: model.GradeA},
	}, true)

	assert.Equal(t, "", label)
}

func TestEnrichLiveToolsWithLocalNodeDependencies(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"demo"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte(`{
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/axios": {"version": "1.14.1"}
  }
}`), 0o644))

	prevWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() {
		_ = os.Chdir(prevWD)
	})

	require.NoError(t, os.WriteFile(filepath.Join(tmp, "server.js"), []byte(`console.log("hello")`), 0o644))

	tools := enrichLiveToolsWithLocalNodeDependencies([]string{"node", "./server.js"}, []model.UnifiedTool{{
		Name: "deploy_site",
	}})
	require.Len(t, tools, 1)
	visibility, note := analyzer.DependencyVisibilityForTool(tools[0])
	assert.Equal(t, "Verified from local lockfile", visibility)
	assert.Contains(t, note, "Local dependency artifacts scanned")

	rawDeps, ok := tools[0].Metadata["dependencies"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, rawDeps, 1)
	assert.Equal(t, "axios", rawDeps[0]["name"])
	assert.Equal(t, "local_lockfile", rawDeps[0]["source"])
}

func TestEnrichLiveToolsWithLocalNodeDependencies_DoesNotUseCallerCWD(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"demo"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte(`{
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/axios": {"version": "1.14.1"}
  }
}`), 0o644))

	prevWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() {
		_ = os.Chdir(prevWD)
	})

	tools := enrichLiveToolsWithLocalNodeDependencies([]string{"npx", "-y", "@modelcontextprotocol/server-memory"}, []model.UnifiedTool{{
		Name: "memory",
	}})
	require.Len(t, tools, 1)

	visibility, note := analyzer.DependencyVisibilityForTool(tools[0])
	assert.Equal(t, "No dependency data", visibility)
	assert.Contains(t, note, "No metadata.dependencies or repo_url")
	_, hasDeps := tools[0].Metadata["dependencies"]
	assert.False(t, hasDeps)
}

func TestRunScan_ServerRequiresUnsafeLiveScanOptIn(t *testing.T) {
	err := runScan(context.Background(), scanOpts{
		serverCmd: `npx -y @modelcontextprotocol/server-memory`,
		protocol:  "mcp",
		output:    "text",
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--allow-unsafe-live-scan")
}

func TestParseYarnLockfile_ParsesYarnBerryEntries(t *testing.T) {
	tmp := t.TempDir()
	lockfile := filepath.Join(tmp, "yarn.lock")
	require.NoError(t, os.WriteFile(lockfile, []byte(`
__metadata:
  version: 8

"axios@npm:^1.14.1":
  version: 1.14.1

"@scope/sdk@npm:^2.3.4":
  version: 2.3.4
`), 0o644))

	deps, err := parseYarnLockfile(lockfile)
	require.NoError(t, err)
	require.Len(t, deps, 2)

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name] = dep.Version
	}
	assert.Equal(t, "1.14.1", got["axios"])
	assert.Equal(t, "2.3.4", got["@scope/sdk"])
}

func TestParsePNPMLockfile_StripsPeerDependencySuffix(t *testing.T) {
	tmp := t.TempDir()
	lockfile := filepath.Join(tmp, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lockfile, []byte(`
lockfileVersion: '9.0'
packages:
  /axios@1.14.1:
    resolution: {integrity: sha512-abc}
  /@scope/sdk@2.3.4(axios@1.14.1):
    resolution: {integrity: sha512-def}
`), 0o644))

	deps, err := parsePNPMLockfile(lockfile)
	require.NoError(t, err)
	require.Len(t, deps, 2)

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name] = dep.Version
	}
	assert.Equal(t, "1.14.1", got["axios"])
	assert.Equal(t, "2.3.4", got["@scope/sdk"])
}

func TestParseRequirementsFile_StripsMarkersAndInlineComments(t *testing.T) {
	tmp := t.TempDir()
	requirements := filepath.Join(tmp, "requirements.txt")
	require.NoError(t, os.WriteFile(requirements, []byte(`
django==4.2.0 # security fixture
Flask==2.3.1 ; python_version >= "3.8"
requests[security]==2.32.0
urllib3===2.0.0
requests>=2.28.0
`), 0o644))

	deps, err := parseRequirementsFile(requirements)
	require.NoError(t, err)
	require.Len(t, deps, 4)

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name] = dep.Version
	}
	assert.Equal(t, "4.2.0", got["django"])
	assert.Equal(t, "2.3.1", got["Flask"])
	assert.Equal(t, "2.32.0", got["requests"])
	assert.Equal(t, "2.0.0", got["urllib3"])
}
