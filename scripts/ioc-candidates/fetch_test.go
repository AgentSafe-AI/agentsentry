package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildCandidates_Golden(t *testing.T) {
	vulns := loadFixtureVulns(t, "osv-response.json")
	existing := loadExistingBlacklist(t, "existing.json")

	now := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	got := buildCandidates(vulns, "npm", existing, now, 24*time.Hour, "HIGH")

	wantData, err := os.ReadFile(filepath.Join("testdata", "candidates-expected.json"))
	if err != nil {
		t.Fatalf("read expected candidates: %v", err)
	}
	var want []blacklistEntry
	if err := json.Unmarshal(wantData, &want); err != nil {
		t.Fatalf("parse expected candidates: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("candidate count mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if candidateKey(got[i]) != candidateKey(want[i]) ||
			got[i].ID != want[i].ID ||
			got[i].Severity != want[i].Severity ||
			got[i].Action != want[i].Action ||
			got[i].Reason != want[i].Reason ||
			got[i].Link != want[i].Link {
			t.Fatalf("candidate %d mismatch:\n got: %#v\nwant: %#v", i, got[i], want[i])
		}
	}
}

func TestFetchCandidatesWithClient_FeedFailureIsWarning(t *testing.T) {
	cfg := config{
		Since:       24 * time.Hour,
		MinSeverity: "HIGH",
		Ecosystems:  []string{"npm"},
		FeedBaseURL: "http://127.0.0.1:1",
		Now:         time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
	}
	client := &httpClientStub{}
	candidates, warnings, err := fetchCandidatesWithClient(context.Background(), cfg, client, map[string]struct{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected no candidates, got %d", len(candidates))
	}
	if len(warnings) == 0 {
		t.Fatalf("expected warning on feed failure")
	}
}

type httpClientStub struct{}

func (h *httpClientStub) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
}

func loadFixtureVulns(t *testing.T, name string) []osvVulnerability {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var vulns []osvVulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return vulns
}

func loadExistingBlacklist(t *testing.T, name string) map[string]struct{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read existing blacklist fixture: %v", err)
	}
	var entries []blacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("parse existing blacklist fixture: %v", err)
	}
	seen := make(map[string]struct{})
	for _, entry := range entries {
		for _, version := range entry.AffectedVersions {
			seen[strings.ToLower(entry.Ecosystem)+":"+strings.ToLower(entry.Component)+"@"+version] = struct{}{}
		}
	}
	return seen
}
