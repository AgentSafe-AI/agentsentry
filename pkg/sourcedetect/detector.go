package sourcedetect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func DetectEmbeddedMCP(root string, opts Options) (*DetectionResult, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("repo root is required")
	}
	defaults := defaultOptions()
	if opts.MaxFiles == 0 {
		opts.MaxFiles = defaults.MaxFiles
	}
	if opts.MaxFileSizeBytes == 0 {
		opts.MaxFileSizeBytes = defaults.MaxFileSizeBytes
	}
	if opts.MaxMatchesPerLanguage == 0 {
		opts.MaxMatchesPerLanguage = defaults.MaxMatchesPerLanguage
	}
	start := time.Now()
	result := &DetectionResult{
		SchemaVersion: "1.0",
		Mode:          "source_detect",
	}

	matchCountByLanguage := map[string]int{}
	var allEvidence []model.Evidence

	filesScanned, err := walkSourceFiles(root, opts, func(rel, abs string, _ os.DirEntry) error {
		ext := strings.ToLower(filepath.Ext(rel))
		sigs := signatureForExt(ext)
		if len(sigs) == 0 {
			return nil
		}
		content, readErr := os.ReadFile(abs)
		if readErr != nil {
			return nil
		}
		text := string(content)

		for _, sig := range sigs {
			if matchCountByLanguage[sig.Language] >= opts.MaxMatchesPerLanguage {
				continue
			}
			importEv, ok := firstEvidence(text, sig.ImportPatterns, "import")
			if !ok {
				continue
			}
			initEv, ok := firstEvidence(text, sig.InitPatterns, "init")
			if !ok {
				continue
			}

			match := Match{
				Language: sig.Language,
				File:     rel,
				Evidence: []Evidence{importEv, initEv},
			}
			if toolEv, ok := firstEvidence(text, sig.ToolDefPatterns, "tool_definition"); ok {
				match.Evidence = append(match.Evidence, toolEv)
			}
			result.HasEmbeddedMCP = true
			result.Detection.Matches = append(result.Detection.Matches, match)
			matchCountByLanguage[sig.Language]++

			for _, ev := range match.Evidence {
				allEvidence = append(allEvidence, model.Evidence{
					Kind:  ev.Kind,
					Value: fmt.Sprintf("%s:%d", rel, ev.Line),
				})
			}
			break
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	result.Detection.FilesScanned = filesScanned
	result.Detection.Elapsed = time.Since(start).Round(10 * time.Millisecond).String()

	if result.HasEmbeddedMCP {
		result.Findings = []model.Issue{{
			RuleID:      "AS-018",
			Severity:    model.SeverityInfo,
			Code:        "EMBEDDED_MCP_DETECTED",
			Description: "Embedded MCP server detected in source. Tool enumeration is not possible without running the server; manual review required for auth, scope, and input validation.",
			Location:    "source",
			Evidence:    allEvidence,
		}}
	}

	return result, nil
}

func firstEvidence(text string, patterns []*regexp.Regexp, kind string) (Evidence, bool) {
	for _, pattern := range patterns {
		loc := pattern.FindStringIndex(text)
		if loc == nil {
			continue
		}
		line := 1 + strings.Count(text[:loc[0]], "\n")
		snippet := firstLine(text[loc[0]:loc[1]])
		return Evidence{Kind: kind, Line: line, Snippet: snippet}, true
	}
	return Evidence{}, false
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}
