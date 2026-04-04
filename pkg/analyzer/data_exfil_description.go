package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

var dataExfiltrationDescriptionRules = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:transmit|send|forward|post|upload|pipe).{0,80}(?:data|info|content).{0,80}\bto\s+(?:https?://|external\s+\w+|remote\s+\w+|attacker|base64)`),
}

type DataExfilDescriptionChecker struct{}

func NewDataExfilDescriptionChecker() *DataExfilDescriptionChecker {
	return &DataExfilDescriptionChecker{}
}

func (c *DataExfilDescriptionChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-017",
		Title:       "Suspicious Data Exfiltration Description",
		Description: "Detects tool descriptions that suggest sending conversation, content, or user data to explicit external endpoints.",
	}
}

func (c *DataExfilDescriptionChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" || isDataMovementTool(tool.Name) {
		return nil, nil
	}

	for _, pattern := range dataExfiltrationDescriptionRules {
		if pattern.MatchString(desc) {
			matched := pattern.FindString(desc)
			return []model.Issue{{
				RuleID:      "AS-017",
				ToolName:    tool.Name,
				Severity:    model.SeverityMedium,
				Code:        "SUSPICIOUS_DATA_EXFIL_DESCRIPTION",
				Description: "possible external data exfiltration language detected in tool description",
				Location:    "description",
				Evidence: []model.Evidence{
					{Kind: "description_pattern", Value: pattern.String()},
					{Kind: "description_match", Value: matched},
				},
			}}, nil
		}
	}

	return nil, nil
}
