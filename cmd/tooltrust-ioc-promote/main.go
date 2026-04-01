package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type candidateIOC struct {
	Ecosystem       string   `json:"ecosystem"`
	IOCType         string   `json:"ioc_type"`
	Value           string   `json:"value"`
	Confidence      string   `json:"confidence"`
	Reason          string   `json:"reason"`
	Source          string   `json:"source"`
	FirstSeen       string   `json:"first_seen"`
	SuggestedAction string   `json:"suggested_action"`
	PromoteTo       string   `json:"promote_to"`
	BlacklistID     string   `json:"blacklist_id,omitempty"`
	AffectedVers    []string `json:"affected_versions,omitempty"`
	Action          string   `json:"action,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	Notes           string   `json:"notes,omitempty"`
}

type npmIOCEntry struct {
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	Reason          string `json:"reason"`
	Confidence      string `json:"confidence,omitempty"`
	Source          string `json:"source,omitempty"`
	FirstSeen       string `json:"first_seen,omitempty"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

type blacklistEntry struct {
	ID               string   `json:"id"`
	Component        string   `json:"component"`
	Ecosystem        string   `json:"ecosystem"`
	AffectedVersions []string `json:"affected_versions"`
	Action           string   `json:"action"`
	Severity         string   `json:"severity"`
	Reason           string   `json:"reason"`
	Link             string   `json:"link"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tooltrust-ioc-promote <candidate-json-file>")
	}

	candidatePath := args[0]
	data, err := os.ReadFile(candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate file: %w", err)
	}

	var candidates []candidateIOC
	if unmarshalErr := json.Unmarshal(data, &candidates); unmarshalErr != nil {
		return fmt.Errorf("parse candidate file: %w", unmarshalErr)
	}
	if len(candidates) == 0 {
		return errors.New("candidate file is empty")
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get cwd: %w", err)
	}
	npmIOCPath := filepath.Join(repoRoot, "pkg", "analyzer", "data", "npm_iocs.json")
	blacklistPath := filepath.Join(repoRoot, "pkg", "analyzer", "data", "blacklist.json")

	current, err := readNPMIOCs(npmIOCPath)
	if err != nil {
		return err
	}
	blacklist, err := readBlacklist(blacklistPath)
	if err != nil {
		return err
	}

	seen := make(map[string]bool, len(current))
	for _, entry := range current {
		seen[strings.ToLower(entry.Name)] = true
	}
	seenBlacklist := make(map[string]bool, len(blacklist))
	for i := range blacklist {
		entry := blacklist[i]
		seenBlacklist[strings.ToLower(entry.Ecosystem)+":"+strings.ToLower(entry.Component)+":"+strings.Join(entry.AffectedVersions, ",")] = true
	}

	var addedNPMIOCs int
	var addedBlacklist int
	for i := range candidates {
		candidate := candidates[i]
		if validateErr := validateCandidate(candidate); validateErr != nil {
			return fmt.Errorf("invalid candidate %q: %w", candidate.Value, validateErr)
		}
		switch candidate.PromoteTo {
		case "npm_iocs":
			if !strings.EqualFold(candidate.Ecosystem, "npm") {
				continue
			}
			if candidate.IOCType != "package_name" && candidate.IOCType != "dependency_name" {
				continue
			}

			name := strings.TrimSpace(candidate.Value)
			if seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			current = append(current, npmIOCEntry{
				Ecosystem:       "npm",
				Name:            name,
				Reason:          strings.TrimSpace(candidate.Reason),
				Confidence:      strings.TrimSpace(candidate.Confidence),
				Source:          strings.TrimSpace(candidate.Source),
				FirstSeen:       strings.TrimSpace(candidate.FirstSeen),
				SuggestedAction: strings.TrimSpace(candidate.SuggestedAction),
			})
			addedNPMIOCs++
		case "blacklist":
			if len(candidate.AffectedVers) == 0 {
				return fmt.Errorf("invalid candidate %q: missing affected_versions for blacklist promotion", candidate.Value)
			}
			if strings.TrimSpace(candidate.BlacklistID) == "" {
				return fmt.Errorf("invalid candidate %q: missing blacklist_id for blacklist promotion", candidate.Value)
			}
			action := strings.ToUpper(strings.TrimSpace(candidate.Action))
			if action != "BLOCK" && action != "WARN" {
				return fmt.Errorf("invalid candidate %q: blacklist action must be BLOCK or WARN", candidate.Value)
			}
			severity := strings.ToUpper(strings.TrimSpace(candidate.Severity))
			switch severity {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW":
			default:
				return fmt.Errorf("invalid candidate %q: blacklist severity must be CRITICAL/HIGH/MEDIUM/LOW", candidate.Value)
			}

			key := strings.ToLower(candidate.Ecosystem) + ":" + strings.ToLower(candidate.Value) + ":" + strings.Join(candidate.AffectedVers, ",")
			if seenBlacklist[key] {
				continue
			}
			seenBlacklist[key] = true
			blacklist = append(blacklist, blacklistEntry{
				ID:               strings.TrimSpace(candidate.BlacklistID),
				Component:        strings.TrimSpace(candidate.Value),
				Ecosystem:        strings.TrimSpace(candidate.Ecosystem),
				AffectedVersions: append([]string(nil), candidate.AffectedVers...),
				Action:           action,
				Severity:         severity,
				Reason:           strings.TrimSpace(candidate.Reason),
				Link:             strings.TrimSpace(candidate.Source),
			})
			addedBlacklist++
		default:
			continue
		}
	}

	sort.Slice(current, func(i, j int) bool {
		return strings.ToLower(current[i].Name) < strings.ToLower(current[j].Name)
	})

	out, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal npm_iocs.json: %w", err)
	}
	out = append(out, '\n')
	if writeErr := os.WriteFile(npmIOCPath, out, 0o644); writeErr != nil {
		return fmt.Errorf("write npm_iocs.json: %w", writeErr)
	}
	sort.Slice(blacklist, func(i, j int) bool {
		if strings.EqualFold(blacklist[i].Ecosystem, blacklist[j].Ecosystem) {
			return strings.ToLower(blacklist[i].Component) < strings.ToLower(blacklist[j].Component)
		}
		return strings.ToLower(blacklist[i].Ecosystem) < strings.ToLower(blacklist[j].Ecosystem)
	})
	blacklistOut, err := json.MarshalIndent(blacklist, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal blacklist.json: %w", err)
	}
	blacklistOut = append(blacklistOut, '\n')
	if err := os.WriteFile(blacklistPath, blacklistOut, 0o644); err != nil {
		return fmt.Errorf("write blacklist.json: %w", err)
	}

	fmt.Printf("Promoted %d npm IOC candidate(s) into %s\n", addedNPMIOCs, npmIOCPath)
	fmt.Printf("Promoted %d blacklist candidate(s) into %s\n", addedBlacklist, blacklistPath)
	return nil
}

func readNPMIOCs(path string) ([]npmIOCEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read npm_iocs.json: %w", err)
	}
	var entries []npmIOCEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse npm_iocs.json: %w", err)
	}
	return entries, nil
}

func readBlacklist(path string) ([]blacklistEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read blacklist.json: %w", err)
	}
	var entries []blacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse blacklist.json: %w", err)
	}
	return entries, nil
}

func validateCandidate(candidate candidateIOC) error {
	if strings.TrimSpace(candidate.Ecosystem) == "" {
		return errors.New("missing ecosystem")
	}
	if strings.TrimSpace(candidate.IOCType) == "" {
		return errors.New("missing ioc_type")
	}
	if strings.TrimSpace(candidate.Value) == "" {
		return errors.New("missing value")
	}
	if strings.TrimSpace(candidate.Reason) == "" {
		return errors.New("missing reason")
	}
	if strings.TrimSpace(candidate.Source) == "" {
		return errors.New("missing source")
	}
	if strings.TrimSpace(candidate.FirstSeen) == "" {
		return errors.New("missing first_seen")
	}
	if _, err := time.Parse("2006-01-02", candidate.FirstSeen); err != nil {
		return fmt.Errorf("invalid first_seen: %w", err)
	}
	return nil
}
