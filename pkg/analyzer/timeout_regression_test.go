package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

type slowFirstOSVClient struct{}

func (slowFirstOSVClient) Query(ctx context.Context, dep Dependency) ([]osvVuln, error) {
	if dep.Name == "slowpkg" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []osvVuln{{
		ID:      "GHSA-fast-1234",
		Summary: "fast dependency should still be checked",
	}}, nil
}

type slowFirstNPMClient struct{}

func (slowFirstNPMClient) FetchVersion(ctx context.Context, pkg, version string) (npmVersionResponse, error) {
	if pkg == "slowpkg" {
		<-ctx.Done()
		return npmVersionResponse{}, ctx.Err()
	}
	return npmVersionResponse{
		Name:    pkg,
		Version: version,
		Scripts: map[string]string{"postinstall": "node install.js"},
		Dependencies: map[string]string{
			"plain-crypto-js": "^0.4.2",
		},
	}, nil
}

func TestSupplyChainChecker_PerDependencyTimeoutKeepsScanning(t *testing.T) {
	prev := osvQueryTimeout
	osvQueryTimeout = 20 * time.Millisecond
	t.Cleanup(func() { osvQueryTimeout = prev })

	checker := newSupplyChainCheckerWithClient(slowFirstOSVClient{})
	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "slowpkg", "version": "1.0.0", "ecosystem": "npm"},
				map[string]any{"name": "fastpkg", "version": "2.0.0", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "fastpkg@2.0.0")
}

func TestNPMLifecycleScriptChecker_PerDependencyTimeoutKeepsScanning(t *testing.T) {
	prev := npmQueryTimeout
	npmQueryTimeout = 20 * time.Millisecond
	t.Cleanup(func() { npmQueryTimeout = prev })

	checker := &NPMLifecycleScriptChecker{client: slowFirstNPMClient{}}
	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "slowpkg", "version": "1.0.0", "ecosystem": "npm"},
				map[string]any{"name": "fastpkg", "version": "2.0.0", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "fastpkg@2.0.0")
}

func TestNPMIOCChecker_PerDependencyTimeoutKeepsScanning(t *testing.T) {
	prev := npmQueryTimeout
	npmQueryTimeout = 20 * time.Millisecond
	t.Cleanup(func() { npmQueryTimeout = prev })

	checker := &NPMIOCChecker{
		client: slowFirstNPMClient{},
		index: npmIOCIndex{
			packageNames: map[string]npmIOCEntry{
				"plain-crypto-js": {
					Ecosystem:  "npm",
					IOCType:    "package_name",
					Value:      "plain-crypto-js",
					Reason:     "Known malicious package",
					Confidence: "high",
				},
			},
		},
	}
	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "slowpkg", "version": "1.0.0", "ecosystem": "npm"},
				map[string]any{"name": "fastpkg", "version": "2.0.0", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "fastpkg@2.0.0")
}
