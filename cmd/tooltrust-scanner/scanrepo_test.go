package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/sourcedetect"
)

func TestRunScanRepo_JSONOutput(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "embed.json")
	repo := filepath.Join("..", "..", "pkg", "sourcedetect", "testdata", "fixtures", "go-embedded")

	err := runScanRepo(t.Context(), scanRepoOpts{
		repoDir:    repo,
		output:     "json",
		outputFile: tmp,
	})
	require.NoError(t, err)

	var got sourcedetect.DetectionResult
	raw, err := os.ReadFile(tmp)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.True(t, got.HasEmbeddedMCP)
	require.NotEmpty(t, got.Findings)
	assert.Equal(t, "AS-018", got.Findings[0].RuleID)
}
