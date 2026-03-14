# Universal AI Agent Skill: Pre-Commit CI/CD Guard

**Target Agents:** Cursor, Antigravity, Kiro, Claude Code, Codex, Copilot.

## 🎯 Core Directive
Whenever the user asks you to "commit", "push", "create a PR", or indicates that a coding task is "finished", you MUST autonomously verify the codebase to prevent CI/CD pipeline failures.

## 🛠️ The Skill (Action)
Before generating any `git commit` commands or finalizing the task, you MUST execute the following command in the terminal:

```bash
make check
```

## 🚦 Execution Rules
1. **If `make check` FAILS (non-zero exit code):**
   - DO NOT proceed with the commit.
   - Read the error output, autonomously fix the code (e.g., fix broken tests, resolve linting issues), and run `make check` again.
2. **If `make check` SUCCEEDS:**
   - Proceed to stage the files (`git add`) and generate a concise, conventional commit message.

## ⚠️ Constraint
Never skip this verification step unless the user explicitly commands `[SKIP-CI]`.
