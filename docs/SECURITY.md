# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| v0.1.x  | :white_check_mark: |
| &lt; v0.1 | :x:              |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in ToolTrust Scanner:

1. **Email** the maintainers with details. You can reach us via:
   - Open an issue with the `security` label and mark it as **private** if your GitHub org supports it, or
   - Email the repository owner (see the [AgentSafe-AI organization](https://github.com/AgentSafe-AI) profile for contact options).

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment (e.g., what an attacker could do)
   - Suggested fix (if any)

3. **Expected response**: We aim to acknowledge within 48 hours and provide an initial assessment within 7 days.

4. **Disclosure**: We will coordinate with you on public disclosure. We ask that you give us a reasonable time to address the issue before public disclosure.

## Security-Critical Areas

ToolTrust Scanner is a static analysis tool that scans tool definitions. Areas of particular security interest:

- **Parser behavior** — malformed input handling in `pkg/adapter/*`
- **OSV API interaction** — supply-chain checker (`pkg/analyzer/supply_chain.go`) makes outbound requests; ensure no injection or credential leakage
- **CLI file handling** — `--input` and `--db` paths; avoid path traversal or unexpected file access

## Dependencies

We use `govulncheck` in CI and keep dependencies up to date. Report any dependency-level vulnerabilities through the same channels above.
