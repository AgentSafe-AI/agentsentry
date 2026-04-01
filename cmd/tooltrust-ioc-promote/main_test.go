package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_PromotesNPMIOC(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "pkg", "analyzer", "data"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pkg", "analyzer", "data", "npm_iocs.json"),
		[]byte("[]\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pkg", "analyzer", "data", "blacklist.json"),
		[]byte("[]\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "candidate.json"),
		[]byte(`[
  {
    "ecosystem": "npm",
    "ioc_type": "package_name",
    "value": "plain-crypto-js",
    "confidence": "high",
    "reason": "Known IOC linked to an npm compromise",
    "source": "https://example.com/post",
    "first_seen": "2026-03-31",
    "suggested_action": "flag",
    "promote_to": "npm_iocs"
  }
]`),
		0o644,
	))

	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		_ = os.Chdir(orig)
	})

	require.NoError(t, run([]string{"candidate.json"}))

	data, err := os.ReadFile(filepath.Join(dir, "pkg", "analyzer", "data", "npm_iocs.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "plain-crypto-js")
}

func TestRun_SkipsNonNPMIOCEntries(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "pkg", "analyzer", "data"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pkg", "analyzer", "data", "npm_iocs.json"),
		[]byte("[]\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pkg", "analyzer", "data", "blacklist.json"),
		[]byte("[]\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "candidate.json"),
		[]byte(`[
  {
    "ecosystem": "npm",
    "ioc_type": "domain",
    "value": "evil.example",
    "confidence": "high",
    "reason": "Known IOC domain",
    "source": "https://example.com/post",
    "first_seen": "2026-03-31",
    "suggested_action": "flag",
    "promote_to": "npm_iocs"
  }
]`),
		0o644,
	))

	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		_ = os.Chdir(orig)
	})

	require.NoError(t, run([]string{"candidate.json"}))

	data, err := os.ReadFile(filepath.Join(dir, "pkg", "analyzer", "data", "npm_iocs.json"))
	require.NoError(t, err)
	assert.Equal(t, "[]\n", string(data))
}

func TestRun_PromotesBlacklistEntry(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "pkg", "analyzer", "data"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pkg", "analyzer", "data", "npm_iocs.json"),
		[]byte("[]\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pkg", "analyzer", "data", "blacklist.json"),
		[]byte("[]\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "candidate.json"),
		[]byte(`[
  {
    "ecosystem": "npm",
    "ioc_type": "package_name",
    "value": "axios",
    "confidence": "high",
    "reason": "Confirmed malicious publish",
    "source": "https://example.com/post",
    "first_seen": "2026-03-31",
    "suggested_action": "block",
    "promote_to": "blacklist",
    "blacklist_id": "AXIOS-NPM-COMPROMISE-2026-03-31",
    "affected_versions": ["1.14.1", "0.30.4"],
    "action": "BLOCK",
    "severity": "CRITICAL"
  }
]`),
		0o644,
	))

	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		_ = os.Chdir(orig)
	})

	require.NoError(t, run([]string{"candidate.json"}))

	data, err := os.ReadFile(filepath.Join(dir, "pkg", "analyzer", "data", "blacklist.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "AXIOS-NPM-COMPROMISE-2026-03-31")
	assert.Contains(t, string(data), "\"affected_versions\": [")
}
