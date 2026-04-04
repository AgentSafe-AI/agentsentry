# Changelog

All notable changes to tooltrust-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.3.6] - 2026-04-04

### Fixed
- **AS-006 false positives**: tools with names like `evaluate_guardrail`,
  `analyze_code_security`, `resolve-library-id`, `code_context`, and
  `code_snippet` are no longer falsely flagged as arbitrary code execution.
  Added safe-name prefixes, safe-name substrings, description-confirms-execution
  gating, and description negation checks. The `code snippet` keyword is now
  gated behind execution verbs (`run`/`execute`/`eval`).

### Changed
- **AS-001 split**: data exfiltration findings are now reported under a separate
  sub-rule for clearer triage.

---

## [0.3.4] - 2026-04-02

### Added
- **Finding evidence**: findings can now carry compact static evidence, including
  matched permission values, prompt-injection description matches, arbitrary-code
  name/description patterns, and compromised package/version blacklist hits.
- **Behavior context**: scanner policies now summarize what a tool appears able
  to do, including `reads_env`, `reads_files`, `writes_files`,
  `executes_commands`, and `uses_network`.
- **Destination context**: scanner policies now classify where a tool may send
  data, including dynamic URL inputs, email recipients, webhook/callback/SMTP
  destinations, and hardcoded API, webhook, email-recipient, or domain targets.
- **Evidence roadmap**: added an implementation roadmap for evidence, behavior,
  and confirmed-malicious classification in `docs/EVIDENCE_ROADMAP.md`.

### Changed
- **CLI output readability**: `scan` output now emphasizes the per-tool decision
  first, adds a short `Why approval`/`Why blocked` summary for flagged tools,
  removes raw score noise from tool headers, and suppresses repeated hints from
  the same rule within a single tool.
- **Evidence rendering**: CLI and MCP text output now show only compact,
  non-redundant evidence so scans stay readable while still explaining why a
  finding matched.
- **Behavior/destination propagation**: gateway policy JSON now exposes behavior,
  destination, and dependency-visibility context for downstream consumers such
  as ToolTrust Directory.

### Fixed
- **CLI noise for clean tools**: `ALLOW` / grade-A tools no longer show
  low-signal dependency visibility noise or duplicate evidence/hint lines.
- **Destination false positives**: destination classification now avoids
  mistaking code-like strings such as `process.env` for real outbound targets.
- **Developer docs consistency**: `DEVELOPER.md`, `CONTRIBUTING.md`, and related
  docs were cleaned up so architecture, contribution flow, and rule references
  point to the current code paths.

---

## [0.2.3] - 2026-03-25

### Fixed
- **MCP per-tool findings**: scan summary now lists every tool with its action emoji
  (✅/⚠️/🚫), grade, score, and individual findings — previously only non-ALLOW tools
  were shown. Applies to `tooltrust_scan_server`, `tooltrust_scanner_scan`, and
  `tooltrust_scan_config`.
- **CLI severity emojis**: reverted grade-A muting — all tools now show real severity
  emojis (🔴/⚠️/🔵) regardless of grade, matching MCP output behaviour.

---

## [0.2.2] - 2026-03-24

### Fixed
- **Grade-A findings display**: tools that pass (grade A / ActionAllow) now show
  findings with an `ℹ️` info icon instead of alarming ⚠️/🔴 severity emojis. Applies
  to both the CLI scanner and the MCP binary.
- **Summary box alignment**: removed double-width emoji characters (✅ ⚠️ 🚫) from
  the summary box format strings; replaced with plain text labels so box borders
  render flush in all terminal emulators.
- **CI/CD pipeline**: `cmd/tooltrust-scanner/gate.go` was silently excluded by a
  bare `tooltrust-scanner` entry in `.gitignore` matching the `cmd/tooltrust-scanner/`
  path component. Fixed by anchoring to `/tooltrust-scanner` and `/tooltrust-mcp`.

### Added
- **Pre-hook integration patterns** in README: shell alias (`mcp-add`) and git
  pre-commit hook that auto-scans new servers added to `.mcp.json`.

### Changed
- **Go toolchain bumped to go1.26.1** to resolve four stdlib vulnerabilities
  (GO-2026-4599, GO-2026-4600, GO-2026-4601, GO-2026-4602) in `crypto/x509`,
  `net/url`, and `os`.

---

## [0.2.1] - 2026-03-23

### Fixed
- **AS-006 false negative**: tool names ending in `_execute` (e.g. `python_execute`)
  now correctly trigger arbitrary code execution detection.
- **AS-010 false positives**: pagination cursor parameters (`pageToken`, `next_token`,
  `cursor`, `continuation_token`, `sync_token`, `resume_token`) are no longer flagged
  as secret handling risks.

---

## [0.2.0] - 2026-03-22

### Added
- **`tooltrust_scan_config` MCP tool**: reads Claude Code MCP config (`.mcp.json`
  or `~/.claude.json`), scans all configured servers in parallel, returns a
  summary report. Merges per-server env vars from config, skips self-scan,
  handles server failures gracefully with partial results.
- **`tooltrust_list_rules` MCP tool**: returns the full security rule catalog
  dynamically from registered checkers — no hardcoded lists.
- **`RuleMeta` interface**: each checker now exports its rule ID, title, and
  description via `Meta()`, enabling dynamic rule enumeration across the codebase.
- **28 tests** for all MCP tool handlers (new and existing), covering happy paths,
  error handling, config parsing, self-skip, and edge cases.

### Changed
- **60s scan timeout** enforced on all live server scans via `context.WithTimeout`,
  preventing hung MCP servers from blocking indefinitely. 60s accommodates
  `npx -y` cold cache (~15-20s for package installation).
- **`scanLiveServer` refactored** to accept `[]string` args directly instead of
  a shell-quoted command string. Eliminates lossy round-trip for config-sourced
  commands with spaces in arguments.
- **`--rules` CLI** now dynamically enumerates registered checkers instead of
  using a hardcoded list (previously missing AS-009 and AS-013).
- **Parallel server scanning** in `tooltrust_scan_config` using goroutines —
  all servers scan concurrently with independent 60s timeouts.

## [0.1.15] - 2026-03-21

### Fixed
- **AS-013**: Removed near-duplicate (`TOOL_SHADOWING_NEAR`) detection, which
  had a 13/13 false-positive rate in production. Intra-server near-duplicates
  are intentional API design — get/set pairs (`get-active-layer`/`set-active-layer`),
  data-granularity variants (`getCryptocurrency5MinuteData`/`getCryptocurrency1MinuteData`),
  and indicator variants (`getEMA`/`getSMA`/`getWMA`) all differ by exactly
  one edit and are not attacks. AS-013 now fires only on exact normalized-name
  duplicates, which are unambiguously problematic. Typo-based impersonation
  is handled by AS-009 (Typosquatting), which has a purpose-built corpus.
- Regression tests added for all 13 false positive cases.

---

## [0.1.14] - 2026-03-21

### Fixed
- **AS-009**: Eliminated 12/12 false positives observed in production scans.
  Three targeted heuristic improvements:
  1. **Prefix-extension skip**: if one normalized name is a prefix of the other
     (e.g. `create_relation` / `create_relations`), skip — these are legitimate
     singular/plural tool families, not impersonations.
  2. **Distance-2 length floor raised** from 10 to 15 normalized chars: generic
     `verb_noun` patterns (`list_comments` vs `list_commits`, `pg_describe_table`
     vs `describe_table`, `create_field` vs `create_file`) no longer trigger.
  3. **Same-length distance-1 threshold**: substitution-type typos on short names
     (`git_tag` vs `get_tag`, `git_commit` vs `get_commit`, `search_notes` vs
     `search_nodes`) are now skipped when both names normalize to fewer than 12
     chars. Insertion/deletion typos (different lengths) are always flagged.
- Regression tests added for all 12 false positive cases.

---

## [0.1.13] - 2026-03-21

### Fixed
- **MCP parser**: The JSON Schema `"type"` field may be either a plain string
  (`"string"`) or an array of strings (`["string","null"]`) per the JSON Schema
  spec. The MCP adapter now handles both via a new `FlexType` unmarshaler.
  Previously, Smithery-hosted tools such as `googlesheets` caused a hard parse
  error (`cannot unmarshal array into Go struct field … of type string`), silently
  skipping the tool in the directory pipeline.

---

## [0.1.12] - 2026-03-20

### Fixed
- **AS-010**: Removed bare `"pass"` from the secret-param pattern list. It matched
  `passenger`, `bypass`, `passthrough`, `pass_count`, `compass`, producing false
  positives on common non-secret parameters. Replaced with `"passphrase"`.
- **AS-001**: Tightened `system:` regex from `(?i)system\s*:` to `(?im)^\s*system\s*:`
  so it only matches at the start of a line. Prose like
  "Monitors system: CPU, RAM, disk" no longer triggers a finding.
- **AS-001**: The bare `exfiltrate` pattern now requires a direct object
  (`data`, `info`, `credentials`, `secrets`, `content`, or `results`) within two words,
  preventing false positives on defensive security tools that mention "exfiltration".

### Added
- Regression tests for all three false-positive fixes above.

---

## [0.1.11] - 2026-03-19

### Added
- **AS-009 Typosquatting checker**: detects tool names that closely resemble known
  legitimate tools using edit-distance heuristics.
- **AS-013 Tool Shadowing checker**: flags tools whose names or descriptions appear
  designed to shadow or override higher-priority tools in an agent's tool list.
- **AS-006**: Catch additional false negatives — `run-code` and `run_shortcut` patterns
  now detected.
- ToolTrust shield + Celtic knot logo SVG (`docs/logo.svg`) matching the site's
  emerald color scheme (`#10B981`).

### Fixed
- **AS-006**: Added word boundaries to backtick shell-execution pattern to prevent
  substring false positives.
- **AS-006**: Removed false positive on "execute arbitrary query/request/operation"
  phrasing used in legitimate database/API tools.

---

## [0.1.10] - 2026-03-18

### Added
- Regression tests for AS-006 real-production false positives.

---

## [0.1.9] - 2026-03-17

### Fixed
- **AS-006**: Additional false positive removed — "execute arbitrary query/request/operation".
- **AS-006**: Word-boundary fix for backtick shell pattern.

---

## [0.1.8] - 2026-03-16

### Fixed
- **AS-006**: Removed false positive on "execute arbitrary query/request/operation".

---

## [0.1.7] - 2026-03-15

### Added
- **AS-001**: Phase 1 false-positive reduction — confidence tiers and tool-name
  allowlist. Data-movement tools (email, reply, forward, …) no longer trigger
  broad exfiltration patterns. Patterns downgraded to Medium severity.

### Fixed
- **AS-001**: Tightened data-exfiltration regex to require an explicit external-
  destination indicator (`https://`, `external`, `remote`, `attacker`, `base64`).

---

## [0.1.6] - 2026-03-14

### Added
- Per-grade action guide printed below scan results in the CLI.
- Actionable issue hints per rule ID (`ruleHint` map in CLI).
- GitHub Actions workflow to auto-update the Homebrew formula on release.

### Fixed
- **AS-002** and **AS-006** recommendation text made actionable with specific
  guidance (enum validation, `approval_required: true`).
- Added `tooltrust-mcp` binary to `.gitignore`.

### Changed
- `--help` output slimmed down; `-r`/`--rules` flag added for full rule catalog.
- `-v` flag added for version output.

---

## [0.1.5] and earlier

Initial releases establishing the core scanning engine with rules AS-001 through
AS-011. See git log for full history.
