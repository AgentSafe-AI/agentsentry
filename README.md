# ToolTrust Scanner

[![CI](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner)](https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

**The security scanner for AI agent tool definitions.**

AI agents blindly trust the tools they call. A single poisoned tool definition can hijack an agent, exfiltrate data, or silently escalate privileges. ToolTrust Scanner intercepts tool definitions *before* execution and blocks threats at the source.

**Used by** — [ToolTrust Directory](https://github.com/AgentSafe-AI/tooltrust-directory): 100+ MCP servers and AI tools with verified A–F security grades.

---

## Scan catalog

> Full specification and severity weights: [ToolTrust Methodology v1.0](https://github.com/AgentSafe-AI/tooltrust-directory/blob/main/docs/methodology.md)

| Rule | ID | Solves |
|------|----|--------|
| 🛡️ **Tool Poisoning** | AS-001 | Agents manipulated by malicious instructions hidden in tool descriptions (`ignore previous instructions`, `system:`, `<INST>`) |
| 🔑 **Permission Surface** | AS-002 | Tools declaring `exec`, `network`, `db`, or `fs` far beyond their stated purpose — or exposing an unnecessarily broad input schema |
| 📐 **Scope Mismatch** | AS-003 | Tool names that contradict their permissions, confusing the agent about what a tool actually does (`read_config` secretly holding `exec`) |
| 📦 **Supply Chain (CVE)** | AS-004 | Third-party libraries bundled by a tool that carry known CVE vulnerabilities — queried live from the [OSV database](https://osv.dev) |
| 🔓 **Privilege Escalation** | AS-005 | OAuth/token scopes broader than the tool's stated purpose (`admin`, `:write` wildcards) or description-level escalation signals (`sudo`, `impersonate`) |
| ⚡ **Arbitrary Code Execution** | AS-006 | Tools that can execute arbitrary script/code (`evaluate_script`, `execute javascript`, `eval`, `run script`, `browser injection`) — risk equivalent to exec |
| 🗝️ **Secret Handling** | AS-010 | Input parameters that accept API keys, passwords, or tokens (leakage risk in agent traces) and descriptions that suggest credentials are logged or stored insecurely |
| ⚡ **DoS Resilience** | AS-011 | Network or execution tools that declare no rate-limit, timeout, or retry configuration — creating runaway resource consumption risk |

## Risk grades

$$\text{RiskScore} = \sum_{i=1}^{n} \left( \text{SeverityWeight}_i \times \text{FindingCount}_i \right)$$

| Weight | Severity | Example trigger |
|--------|----------|-----------------|
| **25** | CRITICAL | Prompt injection (AS-001), arbitrary code execution (AS-006) |
| **15** | HIGH | `exec` / `network` permission (AS-002), scope mismatch (AS-003), broad OAuth scope (AS-005) |
| **8** | MEDIUM | Insecure secret handling (AS-010) |
| **2** | LOW | Over-broad schema (AS-002), missing rate-limit (AS-011) |

| Grade | Score | Gateway action |
|-------|-------|----------------|
| **A** | 0–9 | `ALLOW` |
| **B** | 10–24 | `ALLOW` + rate limit |
| **C** | 25–49 | `REQUIRE_APPROVAL` |
| **D** | 50–74 | `REQUIRE_APPROVAL` |
| **F** | 75+ | `BLOCK` |

---

## 🚀 Quick Start

**Install via automated script (macOS / Linux):**
```bash
curl -fsSL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash
```

### 🤖 For CI/CD (Version Pinning)

To ensure pipeline stability, it is highly recommended to pin a specific version of ToolTrust Scanner:

```bash
# Install a specific version (e.g., v1.0.0)
curl -fsSL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash -s -- v1.0.0
```

**Run your first scan:**
```bash
tooltrust scan --input tools.json
```

---

## Output (ToolTrust Directory schema v1.0)

```json
{
  "schema_version": "1.0",
  "policies": [
    {
      "tool_name": "run_shell",
      "action": "BLOCK",
      "score": {
        "risk_score": 80,
        "grade": "F",
        "findings": [
          { "rule_id": "AS-001", "severity": "CRITICAL", "code": "TOOL_POISONING",
            "description": "possible prompt injection: pattern matched ignore.*instructions",
            "location": "description" },
          { "rule_id": "AS-002", "severity": "HIGH", "code": "HIGH_RISK_PERMISSION",
            "location": "permissions" },
          { "rule_id": "AS-004", "severity": "CRITICAL", "code": "SUPPLY_CHAIN_CVE",
            "description": "CVE-2024-1234 in lodash@4.17.15: Prototype pollution" }
        ]
      }
    }
  ],
  "summary": {
    "total": 3, "allowed": 1, "require_approval": 1, "blocked": 1,
    "scanned_at": "2026-02-27T10:00:00Z"
  }
}
```

---

## Roadmap

- **v0.2** — Additional protocol adapters (OpenAI Functions, Markdown Skills, A2A)
- **v0.3** — REST API · ToolTrust Directory sync · certified reports
- **v0.4** — K8s + gVisor sandbox for dynamic behavioural analysis
- **v0.5** — Public MCP/Skills Security Directory (searchable by grade)
- **v1.0** — Browser extension · webhook gateway · signed scan certificates

---

[Developer guide](docs/DEVELOPER.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Security](SECURITY.md) · [License: MIT](LICENSE) © 2026 AgentSafe-AI
