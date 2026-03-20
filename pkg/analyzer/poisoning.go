package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/deepscan"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// injectionPatterns are compiled regexes that signal prompt injection attempts.
var injectionPatterns = []*regexp.Regexp{
	// "ignore previous instructions", "disregard your instructions", "bypass filters"
	regexp.MustCompile(`(?i)(ignore|disregard|bypass)\s+(?:\w+\s+){0,3}(instructions?|prompts?|context|rules?|guidelines?|restrictions?|filters?)`),
	regexp.MustCompile(`(?i)system\s*:`),
	regexp.MustCompile(`(?i)<\s*INST\s*>`),
	regexp.MustCompile(`(?i)\[INST\]`),
	regexp.MustCompile(`(?i)act\s+as\s+(an?\s+)?(admin|root|superuser|privileged)`),
	regexp.MustCompile(`(?i)forget\s+(your|all|previous)\s+(instructions?|context|rules?|training)`),
	regexp.MustCompile(`(?i)you\s+(are\s+now|must\s+now|will\s+now)\s+(act|behave|operate)`),
	regexp.MustCompile(`(?i)exfiltrate`),
	// Jailbreak / Privilege escalation
	regexp.MustCompile(`(?i)(developer|unrestricted)\s+mode`),
	regexp.MustCompile(`(?i)full\s+system\s+access`),
	regexp.MustCompile(`(?i)jailbreak`),
	// Data Exfiltration — requires an explicit external-destination indicator to
	// avoid false positives on legitimate "send X to Y" phrasing in email/messaging tools.
	regexp.MustCompile(`(?i)send.*(history|data|conversation).*to.*(http|url)`),
	regexp.MustCompile(`(?i)(?:transmit|send|forward|post|upload|pipe).{0,80}(?:data|info|content).{0,80}\bto\s+(?:https?://|external\s+\w+|remote\s+\w+|attacker|base64)`),
}

// PoisoningChecker inspects a tool's description for prompt injection signals.
type PoisoningChecker struct {
	enableDeepScan bool
}

// NewPoisoningChecker returns a new PoisoningChecker.
func NewPoisoningChecker(enableDeepScan bool) *PoisoningChecker {
	return &PoisoningChecker{enableDeepScan: enableDeepScan}
}

// Check runs all injection pattern rules against the tool description.
func (c *PoisoningChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" {
		return nil, nil
	}

	var issues []model.Issue
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(desc) {
			issues = append(issues, model.Issue{
				RuleID:      "AS-001",
				ToolName:    tool.Name,
				Severity:    model.SeverityCritical,
				Code:        "TOOL_POISONING",
				Description: "possible prompt injection detected in tool description: pattern matched: " + pattern.String(),
				Location:    "description",
			})
			// One finding per tool is sufficient for a poisoning verdict.
			break
		}
	}

	if len(issues) == 0 && c.enableDeepScan {
		if _, found := deepscan.Analyze(desc); found {
			issues = append(issues, model.Issue{
				RuleID:      "AS-001",
				ToolName:    tool.Name,
				Severity:    model.SeverityCritical,
				Code:        "TOOL_POISONING",
				Description: "semantic AI analysis detected deep prompt injection in tool description",
				Location:    "description",
			})
		}
	}

	return issues, nil
}
