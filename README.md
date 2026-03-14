# ToolTrust Scanner

[![CI](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner)](https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)

**Scan MCP servers for prompt injection, data exfiltration, and privilege escalation before your AI agent blindly trusts them.**

[Insert Terminal GIF Here]

## 🚀 Quick Start

**Install via Homebrew:**
```bash
brew install AgentSafe-AI/tooltrust-scanner/tooltrust-scanner
```

*(Alternatively, use `go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest`)*

## 💻 Usage

Scan an MCP server directly by spinning it up:

```bash
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

## 🔍 What it catches

ToolTrust intercepts tool definitions *before* execution and blocks threats at the source.

| ID | Detects |
|----|---------|
| 🛡️&nbsp;**AS&#8209;001** | Prompt poisoning (`ignore previous instructions`, `system:`) |
| 🔑&nbsp;**AS&#8209;002** | Excessive permissions (`exec`, `network`, `db`, `fs` beyond stated purpose) |
| 📐&nbsp;**AS&#8209;003** | Scope mismatch (e.g. `read_config` secretly holding `exec`) |
| 📦&nbsp;**AS&#8209;004** | Supply chain vulnerabilities (CVEs in dependencies via OSV) |
| 🔓&nbsp;**AS&#8209;005** | Privilege escalation (`admin` OAuth scopes, `sudo` keywords) |
| ⚡&nbsp;**AS&#8209;006** | Arbitrary code execution (`evaluate_script`, `execute javascript`) |
| 🗝️&nbsp;**AS&#8209;010** | Insecure secret handling (params accepting keys/passwords) |
| ⚡&nbsp;**AS&#8209;011** | DoS resilience (missing rate-limits or timeouts) |

## 🤝 GitHub Actions

Integrate into your CI/CD to block high-risk tools automatically:

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
```

---

[Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE) © 2026 AgentSafe-AI
