# AgentSentry — Developer Guide

## Prerequisites

- Go 1.24+ — [install](https://go.dev/dl/)
- `golangci-lint` v2 — `brew install golangci-lint` or see [golangci-lint docs](https://golangci-lint.run/usage/install/)
- Docker (optional, for image builds)

## Architecture

```
github.com/AgentSafe-AI/agentsentry
│
├── cmd/
│   ├── agentsentry/     CLI — scan, version
│   └── mcpserver/       MCP meta-scanner (exposes agentsentry_scan to AI agents)
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
│   │   └── supply_chain.go AS-004 Supply Chain CVE (OSV API)
│   │
│   ├── gateway/         RiskScore → GatewayPolicy mapper
│   ├── model/           Core types: UnifiedTool · RiskScore · GatewayPolicy
│   ├── storage/         SQLite persistence (modernc.org/sqlite, no CGo)
│   └── sandbox/         K8s + gVisor interface (reserved for v0.4)
│
├── internal/
│   └── jsonschema/      Minimal JSON Schema helpers
│
├── .github/workflows/   CI · Release · Security (govulncheck, gosec)
├── .cursor/skills/      TDD red-green-refactor skill
├── Dockerfile           Multi-stage build → scratch image (~8 MB)
└── Makefile
```

## Make targets

```bash
make test           # race detector + all packages — required before every commit
make test-verbose   # with -v flag
make coverage       # ≥60% threshold enforced on pkg/ + internal/
make coverage-html  # open HTML report in browser
make lint           # golangci-lint (v2)
make fmt            # go fmt ./...
make vet            # go vet ./...
make build          # compile dist/agentsentry + dist/agentsentry-mcp
make cross-compile  # linux/amd64 · linux/arm64 · darwin/amd64 · darwin/arm64 · windows/amd64
make docker         # build ghcr.io/agentsafe-ai/agentsentry:dev
make scan           # self-scan testdata/tools.json (integration check)
make clean          # remove dist/ + coverage files
```

## TDD workflow

This project follows strict **red → green → refactor** TDD.  
Full guide: [`.cursor/skills/tdd-go/SKILL.md`](../.cursor/skills/tdd-go/SKILL.md)

1. **RED** — Write a failing `_test.go` that defines the contract.
2. **GREEN** — Write the minimal code to make it pass (ugly is fine).
3. **REFACTOR** — Clean up; `make test` must still exit 0.

`make test` must exit 0 before every commit. CI enforces this.

## Adding a new scan rule

1. Create `pkg/analyzer/<rule>.go` implementing the `checker` interface:
   ```go
   type checker interface {
       Check(tool model.UnifiedTool) ([]model.Issue, error)
   }
   ```
2. Assign the next available rule ID (e.g. `AS-005`) in each `model.Issue` you return.
3. Register the checker in `NewScanner()` inside `pkg/analyzer/analyzer.go`.
4. Write `pkg/analyzer/<rule>_test.go` — start with the failing test (RED).
5. Update the [Scan catalog](../README.md#scan-catalog) in `README.md`.

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
3. Wire it into `cmd/agentsentry/main.go`'s `switch protocol { ... }`.

## CI/CD

| Workflow | Triggers | Key jobs |
|----------|----------|----------|
| `ci.yml` | push/PR to main | test (race), coverage ≥60%, lint, build, self-scan |
| `release.yml` | `v*.*.*` tags | cross-compile, GitHub Release, Docker push to GHCR |
| `security.yml` | push/PR + weekly | govulncheck, gosec (SARIF), dependency-review, meta-scan |
