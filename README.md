# AgentSentry

[![CI](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/agentsentry/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/agentsentry)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/agentsentry)](https://goreportcard.com/report/github.com/AgentSafe-AI/agentsentry)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

**The security trust layer for MCP servers, OpenAI tools, and AI Skills.**

AI agents blindly trust the tools they call. A single poisoned tool definition can hijack an agent, exfiltrate data, or silently escalate privileges. AgentSentry intercepts tool definitions *before* execution and blocks threats at the source.

---

## Scan catalog

| Rule | ID | Solves |
|------|----|--------|
| 🛡️ **Tool Poisoning** | AS-001 | Agents manipulated by malicious instructions hidden in tool descriptions (`ignore previous instructions`, `system:`, `<INST>`) |
| 🔑 **Permission Surface** | AS-002 | Tools declaring `exec`, `network`, `db`, or `fs` far beyond their stated purpose — or exposing an unnecessarily broad input schema |
| 📐 **Scope Mismatch** | AS-003 | Tool names that contradict their permissions, confusing the agent about what a tool actually does (`read_config` secretly holding `exec`) |
| 📦 **Supply Chain (CVE)** | AS-004 | Third-party libraries bundled by a tool that carry known CVE vulnerabilities — queried live from the [OSV database](https://osv.dev) |

## Risk grades

$$\text{RiskScore} = \sum_{i=1}^{n} \left( \text{SeverityWeight}_i \times \text{FindingCount}_i \right)$$

| Weight | Severity | Example trigger |
|--------|----------|-----------------|
| **25** | CRITICAL | Prompt injection (AS-001) |
| **15** | HIGH | `exec` / `network` permission (AS-002), scope mismatch (AS-003) |
| **8** | MEDIUM | Minor scope issues |
| **3** | LOW | Over-broad schema (AS-002) |

| Grade | Score | Gateway action |
|-------|-------|----------------|
| **A** | 0–10 | `ALLOW` |
| **B** | 11–25 | `ALLOW` + rate limit |
| **C** | 26–50 | `REQUIRE_APPROVAL` |
| **D** | 51–75 | `REQUIRE_APPROVAL` |
| **F** | 76+ | `BLOCK` |

---

## Quick integration

**CLI**
```bash
curl -L https://github.com/AgentSafe-AI/agentsentry/releases/latest/download/agentsentry_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed s/x86_64/amd64/) \
  -o /usr/local/bin/agentsentry && chmod +x /usr/local/bin/agentsentry

agentsentry scan --protocol mcp --input tools.json
```

**GitHub Actions**
```yaml
- name: AgentSentry scan
  run: agentsentry scan --protocol mcp --input testdata/tools.json
```

**MCP meta-scanner** — let Claude scan tools for you:
```bash
agentsentry-mcp   # stdio, exposes agentsentry_scan to any MCP client
```

**Docker**
```bash
docker run --rm -v $(pwd)/tools.json:/tools.json \
  ghcr.io/agentsafe-ai/agentsentry:latest scan --protocol mcp --input /tools.json
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

- **v0.2** — OpenAI Function Calling · Markdown Skills · A2A adapters
- **v0.3** — REST API · ToolTrust Directory sync · certified reports
- **v0.4** — K8s + gVisor sandbox for dynamic behavioural analysis
- **v0.5** — Public MCP/Skills Security Directory (searchable by grade)
- **v1.0** — Browser extension · webhook gateway · signed scan certificates

---

[Developer guide](docs/DEVELOPER.md) · [License: MIT](LICENSE) © 2026 AgentSafe-AI
