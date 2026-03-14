# Contributing to ToolTrust Scanner

Thank you for your interest in contributing. This document explains how to set up your environment, submit changes, and add new scan rules or adapters.

## Prerequisites

- Go 1.26+
- `golangci-lint` v2 — `brew install golangci-lint` or see [golangci-lint docs](https://golangci-lint.run/usage/install/)
- Git

## Development setup

```bash
git clone https://github.com/AgentSafe-AI/tooltrust-scanner.git
cd tooltrust-scanner
go mod download
make test
make lint
```

## Workflow

1. **Fork** the repo and create a branch from `main`.
2. **Make changes** — follow the [TDD workflow](.cursor/skills/tdd-go/SKILL.md): write failing tests first, then implement, then refactor.
3. **Run checks** — `make test` and `make lint` must pass before committing.
4. **Commit** — use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`.
5. **Open a PR** — target `main` and describe your change. Link any related issues.

## Adding a new scan rule

See [docs/DEVELOPER.md#adding-a-new-scan-rule](docs/DEVELOPER.md#adding-a-new-scan-rule) for the step-by-step guide. Summary:

1. Create `pkg/analyzer/<rule>.go` implementing the `checker` interface.
2. Assign the next available rule ID (e.g. `AS-006`) in each `model.Issue`.
3. Register the checker in `NewScanner()` in `pkg/analyzer/analyzer.go`.
4. Write `pkg/analyzer/<rule>_test.go` following TDD.
5. Update the [Scan catalog](README.md#scan-catalog) in `README.md`.

## Adding a new protocol adapter

See [docs/DEVELOPER.md#adding-a-new-protocol-adapter](docs/DEVELOPER.md#adding-a-new-protocol-adapter).

## Code style

- Format: `make fmt` (runs `go fmt`)
- Lint: `make lint` — must pass with zero issues
- Tests: `make test` — race detector enabled; all tests must pass

## Questions

- **Bug reports** — use [GitHub Issues](https://github.com/AgentSafe-AI/tooltrust-scanner/issues).
- **Feature requests** — open an issue with the `enhancement` label.
- **Security** — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
