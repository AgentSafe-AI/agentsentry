package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// writeSarifOutput converts the ScanReport to SARIF format and prints/writes it.
func writeSarifOutput(opts scanOpts, report ScanReport) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return fmt.Errorf("failed to create sarif report: %w", err)
	}

	run := sarif.NewRunWithInformationURI("ToolTrust Scanner", "https://github.com/AgentSafe-AI/tooltrust-scanner")

	run.AddRule("AS-001").WithShortDescription(sarif.NewMultiformatMessageString("Prompt Injection")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-017").WithShortDescription(sarif.NewMultiformatMessageString("Suspicious Data Exfiltration Description")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-002").WithShortDescription(sarif.NewMultiformatMessageString("Dangerous Permission")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-003").WithShortDescription(sarif.NewMultiformatMessageString("Scope Mismatch")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-004").WithShortDescription(sarif.NewMultiformatMessageString("Supply Chain Risk")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-005").WithShortDescription(sarif.NewMultiformatMessageString("Privilege Escalation")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-006").WithShortDescription(sarif.NewMultiformatMessageString("Arbitrary Code Execution")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-010").WithShortDescription(sarif.NewMultiformatMessageString("Secret Handling")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	run.AddRule("AS-011").WithShortDescription(sarif.NewMultiformatMessageString("Missing Rate Limit")).WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")

	sarifReport.AddRun(run)

	for i := range report.Policies {
		policy := report.Policies[i]
		for _, issue := range policy.Score.Issues {
			level := "note"
			switch issue.Severity {
			case model.SeverityCritical, model.SeverityHigh:
				level = "error"
			case model.SeverityMedium:
				level = "warning"
			case model.SeverityLow, model.SeverityInfo:
				level = "note"
			}

			ruleId := issue.RuleID
			if ruleId == "" {
				ruleId = issue.Code // fallback if rule ID is missing
			}

			loc := sarif.NewLocationWithPhysicalLocation(sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(policy.ToolName)))

			result := sarif.NewRuleResult(ruleId).
				WithMessage(sarif.NewTextMessage(issue.Description)).
				WithLevel(level).
				WithLocations([]*sarif.Location{loc})

			run.AddResult(result)
			// go-sarif assigns 'unit(-1)' to RuleIndex if the rule isn't found in tool.driver.rules,
			// causing a uint64 underflow in JSON. We explicitly nil it out.
			result.RuleIndex = nil
		}
	}

	encoded, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sarif json: %w", err)
	}

	if opts.outputFile != "" {
		if writeErr := os.WriteFile(opts.outputFile, encoded, 0o644); writeErr != nil {
			return fmt.Errorf("failed to write output file: %w", writeErr)
		}
	} else {
		fmt.Println(string(encoded))
	}
	return nil
}
