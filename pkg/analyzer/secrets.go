package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// secretParamPatterns are input-schema property names that indicate the tool
// accepts credentials or secrets as parameters.  Passing secrets through tool
// inputs risks them being logged, cached, or leaked in agent traces.
var secretParamPatterns = []string{
	"api_key", "apikey", "api_secret",
	"password", "passwd", "passphrase",
	"token", "auth_token", "access_token", "refresh_token", "bearer",
	"secret", "secret_key",
	"credential", "credentials",
	"private_key", "signing_key",
	"client_secret",
	"session_token", "session_key",
}

// secretParamAllowlist contains parameter names that match secretParamPatterns
// but are actually pagination cursors, not credentials.
var secretParamAllowlist = map[string]bool{
	"pagetoken":          true,
	"page_token":         true,
	"next_token":         true,
	"nexttoken":          true,
	"cursor":             true,
	"next_cursor":        true,
	"nextcursor":         true,
	"continuation_token": true,
	"sync_token":         true,
	"resume_token":       true,
}

// secretDescriptionPatterns detect when a tool description signals that
// credentials are logged or stored in an insecure manner.
var secretDescriptionPatterns = []string{
	"log the api key",
	"store password",
	"print token",
	"output credential",
	"write secret",
	"save password",
	"expose key",
}

// SecretHandlingChecker flags tools that accept credentials as input
// parameters (high leakage risk in agent traces) and descriptions that suggest
// secrets are logged or stored insecurely.
//
// Rule ID: AS-010.
type SecretHandlingChecker struct{}

func (c *SecretHandlingChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-010",
		Title:       "Secret Handling",
		Description: "Flags tools that accept API keys, tokens, or credentials as input parameters, risking exposure in logs or agent traces.",
	}
}

// NewSecretHandlingChecker returns a new SecretHandlingChecker.
func NewSecretHandlingChecker() *SecretHandlingChecker { return &SecretHandlingChecker{} }

// Check scans input schema properties and the tool description for credential
// exposure patterns.
func (c *SecretHandlingChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var issues []model.Issue

	// 1. Input schema: look for parameter names that indicate secrets
	for propName := range tool.InputSchema.Properties {
		nameLower := strings.ToLower(propName)
		if secretParamAllowlist[nameLower] {
			continue
		}
		for _, pattern := range secretParamPatterns {
			if nameLower == pattern || strings.Contains(nameLower, pattern) {
				issues = append(issues, model.Issue{
					RuleID:      "AS-010",
					ToolName:    tool.Name,
					Severity:    model.SeverityHigh,
					Code:        "SECRET_IN_INPUT",
					Description: fmt.Sprintf("input parameter %q appears to accept a secret or credential", propName),
					Location:    fmt.Sprintf("inputSchema.properties.%s", propName),
				})
				break
			}
		}
	}

	// 2. Description: look for insecure secret handling language
	descLower := strings.ToLower(tool.Description)
	for _, pattern := range secretDescriptionPatterns {
		if strings.Contains(descLower, pattern) {
			issues = append(issues, model.Issue{
				RuleID:      "AS-010",
				ToolName:    tool.Name,
				Severity:    model.SeverityMedium,
				Code:        "INSECURE_SECRET_HANDLING",
				Description: fmt.Sprintf("tool description suggests insecure credential handling: %q", pattern),
				Location:    "description",
			})
			break
		}
	}

	return issues, nil
}
