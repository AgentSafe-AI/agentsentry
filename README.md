# AgentSafe

[![CI](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/agentsafe/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/agentsafe)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/agentsafe?v=2)](https://goreportcard.com/report/github.com/AgentSafe-AI/agentsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

**Security scanner and trust gateway for AI agent tool ecosystems.**

AgentSafe scans MCP servers, OpenAI function tools, and Markdown Skills before an AI agent runs them — detecting prompt injection, permission abuse, and scope mismatches. It also powers a public **MCP/Skills Security Directory** where anyone can look up the safety grade of a tool before installing it.

## Why AgentSafe?

In 2026, AI agents routinely call external tools via MCP, Skills, and function-calling APIs. A single malicious or misconfigured tool definition can:

- **Hijack the agent** via prompt injection hidden in the tool description
- **Escalate privileges** by declaring `exec` or `network` permissions far beyond the tool's stated purpose
- **Exfiltrate data** through scope mismatches invisible to the end user

AgentSafe is the security layer that sits between the agent and its tools.

## How it works

```
Tool definition (MCP / OpenAI / Skills)
        │
        ▼
  ┌─────────────┐
  │   Adapter   │  Normalises any protocol → UnifiedTool
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Analyzer   │  Poisoning · Permission Surface · Scope Mismatch
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │   Gateway   │  ALLOW · REQUIRE_APPROVAL · BLOCK + rate limits
  └─────────────┘
```

Each tool receives a **risk score** and a **grade**:

| Grade | Score | Gateway policy |
|-------|-------|----------------|
| A | 0–10 | `ALLOW` |
| B | 11–25 | `ALLOW` + rate limit |
| C | 26–50 | `REQUIRE_APPROVAL` |
| D | 51–75 | `REQUIRE_APPROVAL` |
| F | 76+ | `BLOCK` |

## Architecture

```
agentsafe/
├── cmd/
│   ├── agentsafe/       # CLI — scan, version
│   └── mcpserver/       # AgentSafe as an MCP tool (meta-scanner)
├── pkg/
│   ├── adapter/         # Protocol converters: MCP · OpenAI · Skills · A2A
│   ├── analyzer/        # Scan engine: poisoning · permissions · scope mismatch
│   ├── gateway/         # RiskScore → GatewayPolicy mapper
│   ├── model/           # Core types: UnifiedTool · RiskScore · GatewayPolicy
│   ├── sandbox/         # K8s + gVisor dynamic execution interface (reserved)
│   ├── storage/         # Scan result persistence: SQLite / Postgres  (planned)
│   └── report/          # Certified report generation: Markdown / JSON (planned)
├── internal/
│   ├── jsonschema/      # JSON Schema helpers
│   └── mcp/             # AgentSafe MCP Server implementation
├── web/                 # MCP/Skills Security Directory — Next.js (planned)
├── .github/workflows/   # CI · Release · Security workflows
├── .cursor/skills/      # Project TDD skill (red-green-refactor)
├── Dockerfile
├── Makefile
└── go.mod
```

## Quick Start

### Install (pre-built binary)

```bash
# macOS (Apple Silicon)
curl -L https://github.com/AgentSafe-AI/agentsafe/releases/latest/download/agentsafe_darwin_arm64 \
  -o /usr/local/bin/agentsafe && chmod +x /usr/local/bin/agentsafe

# macOS (Intel)
curl -L https://github.com/AgentSafe-AI/agentsafe/releases/latest/download/agentsafe_darwin_amd64 \
  -o /usr/local/bin/agentsafe && chmod +x /usr/local/bin/agentsafe

# Linux (amd64)
curl -L https://github.com/AgentSafe-AI/agentsafe/releases/latest/download/agentsafe_linux_amd64 \
  -o /usr/local/bin/agentsafe && chmod +x /usr/local/bin/agentsafe
```

### Build from source

```bash
git clone https://github.com/AgentSafe-AI/agentsafe.git
cd agentsafe
make build          # binaries in dist/
```

### Scan an MCP tool list

```bash
agentsafe scan --protocol mcp --input tools.json
```

Example output:

```json
{
  "policies": [
    {
      "ToolName": "run_shell",
      "Action": "REQUIRE_APPROVAL",
      "Score": { "Score": 60, "Grade": "D",
        "Issues": [
          { "Severity": "CRITICAL", "Code": "TOOL_POISONING", ... },
          { "Severity": "HIGH",     "Code": "HIGH_RISK_PERMISSION", ... }
        ]
      }
    }
  ],
  "summary": { "total": 2, "allowed": 1, "requireApproval": 1, "blocked": 0 }
}
```

### Run as MCP Server (meta-scanner)

```bash
agentsafe-mcp
# Stdio transport — connect via any MCP client
# Exposes: agentsafe_scan
```

### Docker

```bash
docker run --rm \
  -v $(pwd)/tools.json:/tools.json \
  ghcr.io/AgentSafe-AI/agentsafe:latest \
  scan --protocol mcp --input /tools.json
```

## Development

```bash
make test           # race detector, required before every commit
make coverage       # coverage report (≥60% enforced on pkg/ + internal/)
make coverage-html  # open HTML report in browser
make lint           # golangci-lint
make fmt vet        # format + vet
make cross-compile  # all 5 platform binaries
```

### TDD Workflow

This project follows strict **red-green-refactor** TDD.
See [`.cursor/skills/tdd-go/SKILL.md`](.cursor/skills/tdd-go/SKILL.md) for the full guide.

1. Write a failing `_test.go` (RED)
2. Write minimal code to pass (GREEN)
3. Refactor without breaking tests (REFACTOR)

`make test` must exit 0 before every commit.

## Roadmap

### v0.2 — Protocol coverage
- [ ] OpenAI Function Calling adapter
- [ ] Markdown Skills adapter (`SKILL.md` frontmatter parsing)
- [ ] A2A protocol support

### v0.3 — Storage & Reports
- [ ] `pkg/storage` — persist scan results to SQLite / Postgres
- [ ] `pkg/report` — generate certified Markdown / JSON / PDF reports
- [ ] REST API for querying historical scan results

### v0.4 — Dynamic Analysis
- [ ] `pkg/sandbox` — K8s + gVisor dynamic execution
- [ ] Syscall and network behaviour capture during sandbox runs

### v0.5 — MCP/Skills Security Directory *(website)*
- [ ] `web/` — Next.js public directory of scanned MCP servers and Skills
- [ ] Search, filter, and browse tools by risk grade
- [ ] One-click scan for any public MCP endpoint or GitHub-hosted Skill
- [ ] Community-submitted tool submissions with automated re-scan on update

### v1.0 — Production Gateway
- [ ] Browser extension for real-time MCP tool inspection
- [ ] Webhook-based gateway integration (block calls before they leave the agent)
- [ ] Signed scan certificates for verified-safe tools

## Contributing

PRs welcome. Please follow the TDD workflow above and ensure `make test` passes.

## License

[MIT](LICENSE) © 2026 AgentSafe-AI
