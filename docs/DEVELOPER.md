# ToolTrust Scanner — Developer Guide

This guide is for people changing ToolTrust internals: analyzers, adapters, output formats, and core data structures.

For local setup, branch / PR flow, and required checks, use [Contributing](./CONTRIBUTING.md).

## Architecture

```
github.com/AgentSafe-AI/tooltrust-scanner
│
├── cmd/
│   ├── tooltrust-scanner/  CLI — scan, gate, version
│   └── tooltrust-mcp/      MCP meta-scanner (exposes scan tools to AI agents)
│
├── pkg/
│   ├── adapter/         Protocol converters → UnifiedTool
│   │   ├── mcp/         MCP tools/list parser          ✅ implemented
│   │   ├── openai/      OpenAI function-calling         🚧 stub
│   │   ├── skills/      Markdown Skills (SKILL.md)      🚧 stub
│   │   └── a2a/         Agent-to-Agent protocol         📋 planned
│   │
│   ├── analyzer/        Scan engine + rule catalog
│   │   ├── engine.go    Engine — context-free public API (NewEngine / Scan)
│   │   ├── analyzer.go  Scanner — context-aware, orchestrates checkers
│   │   ├── poisoning.go AS-001 Tool Poisoning
│   │   ├── permission.go AS-002 Permission Surface
│   │   ├── scope.go     AS-003 Scope Mismatch
│   │   ├── supply_chain.go AS-004 Supply Chain CVE (OSV API)
│   │   ├── privilege.go AS-005 Privilege Escalation
│   │   ├── secrets.go   AS-010 Secret Handling
│   │   └── dos.go       AS-011 DoS Resilience
│   │
│   ├── gateway/         RiskScore → GatewayPolicy mapper
│   ├── model/           Core types: UnifiedTool · RiskScore · GatewayPolicy
│   ├── storage/         SQLite persistence (modernc.org/sqlite, no CGo)
│   └── sandbox/         K8s + gVisor interface (reserved for v0.4)
│
├── internal/
│   └── jsonschema/      Minimal JSON Schema helpers
│
├── testdata/
│   └── tools.json       Sample MCP fixture for E2E testing
│
├── .github/workflows/   CI · Release · Security (govulncheck, gosec)
├── .cursor/skills/      TDD red-green-refactor skill
├── Dockerfile           Multi-stage build → scratch image (~8 MB)
└── Makefile
```

## Key commands

```bash
make test           # race detector + all packages — required before every commit
make lint           # golangci-lint (v2)
make fmt            # go fmt ./...
make build          # compile dist/tooltrust-scanner + dist/tooltrust-scanner-mcp
make scan           # self-scan testdata/tools.json (integration check)
```

## TDD workflow

This project follows strict **red → green → refactor** TDD.  
Full guide: [`.cursor/skills/tdd-go/SKILL.md`](../.cursor/skills/tdd-go/SKILL.md)

1. **RED** — Write a failing `_test.go` that defines the contract.
2. **GREEN** — Write the minimal code to make it pass (ugly is fine).
3. **REFACTOR** — Clean up; `make test` must still exit 0.

Keep the change loop small:

1. Write or update the failing test first.
2. Make the smallest implementation change that turns it green.
3. Refactor only after tests pass.

`make test` must exit 0 before every commit. CI enforces this.

## Adding a new scan rule

1. Create `pkg/analyzer/<rule>.go` implementing the `checker` interface:
   ```go
   type checker interface {
       Check(tool model.UnifiedTool) ([]model.Issue, error)
   }
   ```
2. Assign the next available rule ID (e.g. `AS-006`) in each `model.Issue` you return.
3. Register the checker in `NewScanner()` inside `pkg/analyzer/analyzer.go`.
4. Write `pkg/analyzer/<rule>_test.go` — start with the failing test (RED).
5. Update any user-facing rule references if behavior changed:
   - [README](../README.md)
   - [Rules catalog](./RULES.md)

## ToolTrust Directory JSON schema

All scan output conforms to `schema_version: "1.0"`:

```json
{
  "schema_version": "1.0",
  "policies": [
    {
      "tool_name": "run_shell",
      "action": "BLOCK",
      "rate_limit": null,
      "reason": "",
      "score": {
        "risk_score": 80,
        "grade": "F",
        "findings": [
          {
            "rule_id": "AS-001",
            "severity": "CRITICAL",
            "code": "TOOL_POISONING",
            "description": "possible prompt injection detected in tool description",
            "location": "description"
          }
        ]
      }
    }
  ],
  "summary": {
    "total": 1,
    "allowed": 0,
    "require_approval": 0,
    "blocked": 1,
    "scanned_at": "2026-02-27T10:00:00Z"
  }
}
```

## Adding a new protocol adapter

1. Create `pkg/adapter/<protocol>/adapter.go` implementing `adapter.Adapter`:
   ```go
   type Adapter interface {
       Parse(ctx context.Context, data []byte) ([]model.UnifiedTool, error)
       Protocol() model.ProtocolType
   }
   ```
2. Write a `_test.go` with table-driven cases for valid + invalid inputs.
3. Wire it into `cmd/tooltrust-scanner/main.go`'s `switch protocol { ... }`.

## Notes for docs and UX changes

- If you change CLI or MCP report output, update snapshots or output examples in:
  - [README](../README.md)
  - [npm README](../npm/README.md)
- If you add a rule or change rule semantics, update:
  - [Rules catalog](./RULES.md)
  - [Usage guide](./USAGE.md) when flags or examples change
