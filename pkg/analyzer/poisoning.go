package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/deepscan"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// patternRule pairs an injection-detection regex with the severity it emits.
type patternRule struct {
	pattern  *regexp.Regexp
	severity model.Severity
}

// legitimateDataMovementTools lists tool-name keywords that indicate sending
// or forwarding data is the tool's intended purpose — not an injection signal.
var legitimateDataMovementTools = []string{
	"email", "mail", "reply", "forward", "draft", "message",
	"send", "notification", "webhook", "publish", "broadcast",
}

// suspiciousNameTerms cancels the data-movement skip when found in a tool
// name: a name like "send_to_url" or "forward_to_remote_host" is itself a
// red flag, so the data-exfiltration patterns must still run.
var suspiciousNameTerms = []string{
	"external", "remote", "http", "url", "attacker", "exfil",
}

// injectionRules is the ordered list of AS-001 detection rules.
// AS-001 is reserved for explicit prompt/instruction override patterns.
var injectionRules = []patternRule{
	// ── High-confidence: explicit injection markers ──────────────────────────
	{
		regexp.MustCompile(`(?i)(ignore|disregard|bypass)\s+(?:\w+\s+){0,3}(instructions?|prompts?|context|rules?|guidelines?|restrictions?|filters?)`),
		model.SeverityCritical,
	},
	{regexp.MustCompile(`(?im)^\s*system\s*:`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)<\s*INST\s*>`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)\[INST\]`), model.SeverityCritical},
	{
		regexp.MustCompile(`(?i)act\s+as\s+(an?\s+)?(admin|root|superuser|privileged)`),
		model.SeverityCritical,
	},
	{
		regexp.MustCompile(`(?i)forget\s+(your|all|previous)\s+(instructions?|context|rules?|training)`),
		model.SeverityCritical,
	},
	{
		regexp.MustCompile(`(?i)you\s+(are\s+now|must\s+now|will\s+now)\s+(act|behave|operate)`),
		model.SeverityCritical,
	},
	{regexp.MustCompile(`(?i)exfiltrate\s+(?:\w+\s+){0,2}(?:data|info|credentials?|secrets?|content|results?)`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)(developer|unrestricted)\s+mode`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)full\s+system\s+access`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)jailbreak`), model.SeverityCritical},
}

type PoisoningChecker struct {
	enableDeepScan bool
}

func (c *PoisoningChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-001",
		Title:       "Tool Poisoning / Prompt Injection",
		Description: "Detects malicious instructions embedded in tool descriptions that attempt to hijack agent behavior, exfiltrate data, or override safety constraints.",
	}
}

// NewPoisoningChecker returns a new PoisoningChecker.
func NewPoisoningChecker(enableDeepScan bool) *PoisoningChecker {
	return &PoisoningChecker{enableDeepScan: enableDeepScan}
}

// Check runs all injection-pattern rules against the tool description.
func (c *PoisoningChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" {
		return nil, nil
	}

	var issues []model.Issue
	for _, rule := range injectionRules {
		if rule.pattern.MatchString(desc) {
			matched := rule.pattern.FindString(desc)
			issues = append(issues, model.Issue{
				RuleID:      "AS-001",
				ToolName:    tool.Name,
				Severity:    rule.severity,
				Code:        "TOOL_POISONING",
				Description: "possible prompt injection detected in tool description: pattern matched: " + rule.pattern.String(),
				Location:    "description",
				Evidence: []model.Evidence{
					{Kind: "description_pattern", Value: rule.pattern.String()},
					{Kind: "description_match", Value: matched},
				},
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
				Evidence: []model.Evidence{
					{Kind: "deep_scan", Value: "semantic prompt injection signal in description"},
				},
			})
		}
	}

	return issues, nil
}

// isDataMovementTool returns true when the tool name contains a data-movement
// keyword (email/reply/forward/…) but does NOT also contain an
// external-destination term (url/remote/external/…) that would itself be a
// red flag.  The dual check prevents a malicious tool named "send_to_url"
// or "forward_to_remote_host" from bypassing the data-exfiltration patterns.
func isDataMovementTool(name string) bool {
	nameLower := strings.ToLower(name)
	for _, s := range suspiciousNameTerms {
		if strings.Contains(nameLower, s) {
			return false
		}
	}
	for _, kw := range legitimateDataMovementTools {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	return false
}
