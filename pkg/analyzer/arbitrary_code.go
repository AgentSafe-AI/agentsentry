package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// arbitraryCodeKeywords are exact phrases that imply arbitrary script/code
// execution found in tool name or description.
var arbitraryCodeKeywords = []string{
	"evaluate_script",
	"evaluate script",
	"execute javascript",
	"execute js",
	"execute script",
	"execute code",
	"run script",
	"run code",
	"run shortcut",
	"run_shortcut",
	"browser injection",
	"arbitrary code",
	"arbitrary script",
	"arbitrary command",
	"python code",
	"runs user-provided",
	"code snippet",
}

// arbitraryCodePatterns are compiled regexes for natural language variants
// that the exact keyword list can't cover (e.g. "evaluates a JavaScript expression").
var arbitraryCodePatterns = []*regexp.Regexp{
	// "eval" as a whole word — avoids "retrieval", "revalidate", etc.
	regexp.MustCompile(`(?i)\beval\b`),
	// "evaluates … javascript / js / script / expression / code"
	regexp.MustCompile(`(?i)evaluat\w*\s+\w*\s*(javascript|js|script|expression|code)`),
	// "execute … javascript / js / script"
	// Note: "arbitrary" is intentionally excluded here — "arbitrary" alone is
	// caught by the keywords "arbitrary code/script/command".  Keeping it in
	// the regex caused false positives on GraphQL tools ("execute an arbitrary
	// GraphQL query") and REST clients ("execute an arbitrary API request").
	regexp.MustCompile(`(?i)execut\w*\s+\w*\s*(javascript|js|script)`),
	// "run(s) … javascript / arbitrary … code/script"
	regexp.MustCompile(`(?i)runs?\s+\w*\s*(javascript|arbitrary\s+(code|script))`),
	// "inject … script / code"
	regexp.MustCompile(`(?i)inject\w*\s+\w*\s*(script|code)`),
	// accepts / runs ... python code
	regexp.MustCompile(`(?i)(accepts|runs|executes?).*python\s+code`),
	// page.evaluate() / frame.evaluate() / window.eval — common in CDP/Puppeteer
	regexp.MustCompile(`(?i)(page|frame|window|document)\.(eval|evaluate)\b`),
	// hidden shell command in backticks: `curl ... | bash`, `wget`, `sh`
	// Word boundaries prevent matching "sh" inside words like "shown",
	// "troubleshooting", "publish", "refresh", etc.
	regexp.MustCompile("(?i)`[^`]*\\b(curl|wget|bash|sh)\\b[^`]*`"),
}

// arbitraryCodeNameSuffixes are tool-name suffixes that strongly signal JS
// evaluation (e.g. chrome_evaluate, puppeteer_evaluate, cdp_eval).
var arbitraryCodeNameSuffixes = []string{
	"_evaluate",
	"_eval",
	"_execute",
	"evaluatescript",
	"executescript",
	"executejavascript",
	"_runscript",
}

// ArbitraryCodeChecker detects tools that can execute arbitrary script or
// code (e.g. evaluate_script, execute JavaScript, browser injection).
// These are AS-006 with CRITICAL severity — equivalent risk to exec.
type ArbitraryCodeChecker struct{}

func (c *ArbitraryCodeChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-006",
		Title:       "Arbitrary Code Execution",
		Description: "Flags tools that accept or execute arbitrary scripts, eval patterns, or sandbox escape mechanisms.",
	}
}

// NewArbitraryCodeChecker returns a new ArbitraryCodeChecker.
func NewArbitraryCodeChecker() *ArbitraryCodeChecker { return &ArbitraryCodeChecker{} }

// Check produces an AS-006 finding when name or description signals
// arbitrary code/script execution capability.
func (c *ArbitraryCodeChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	nameLower := strings.ToLower(strings.TrimSpace(tool.Name))
	descLower := strings.ToLower(strings.TrimSpace(tool.Description))

	// 1. Exact keyword match in name (normalised) or description.
	for _, kw := range arbitraryCodeKeywords {
		kwNorm := strings.ReplaceAll(kw, " ", "")
		kwSnake := strings.ReplaceAll(kw, " ", "_")
		nameMatch := strings.Contains(nameLower, kwNorm) ||
			strings.Contains(nameLower, kwSnake) ||
			strings.Contains(nameLower, strings.ReplaceAll(kw, " ", ""))
		descMatch := strings.Contains(descLower, kw)
		if nameMatch || descMatch {
			evidence := []model.Evidence{}
			if nameMatch {
				evidence = append(evidence, model.Evidence{Kind: "tool_name_keyword", Value: kw})
			}
			if descMatch {
				evidence = append(evidence, model.Evidence{Kind: "description_keyword", Value: kw})
			}
			return emitArbitraryCodeFinding(tool.Name, evidence), nil
		}
	}

	// 2. Name-suffix patterns (e.g. chrome_evaluate, cdp_eval).
	for _, suffix := range arbitraryCodeNameSuffixes {
		if strings.HasSuffix(nameLower, suffix) || strings.Contains(nameLower, suffix) {
			return emitArbitraryCodeFinding(tool.Name, []model.Evidence{
				{Kind: "tool_name_suffix", Value: suffix},
			}), nil
		}
	}

	// 3. Regex patterns for natural language variants in description or name.
	combined := nameLower + " " + descLower
	for _, re := range arbitraryCodePatterns {
		if re.MatchString(combined) {
			matched := re.FindString(combined)
			return emitArbitraryCodeFinding(tool.Name, []model.Evidence{
				{Kind: "pattern", Value: re.String()},
				{Kind: "match", Value: matched},
			}), nil
		}
	}

	return nil, nil
}

func emitArbitraryCodeFinding(toolName string, evidence []model.Evidence) []model.Issue {
	return []model.Issue{{
		RuleID:      "AS-006",
		ToolName:    toolName,
		Severity:    model.SeverityCritical,
		Code:        "ARBITRARY_CODE_EXECUTION",
		Description: "tool name or description implies arbitrary script/code execution (evaluate_script, execute javascript, etc.)",
		Location:    "name,description",
		Evidence:    evidence,
	}}
}
