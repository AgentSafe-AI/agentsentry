# IOC Blacklist Auto-Candidate Pipeline

This workflow adds a daily review loop for likely blacklist entries without silently editing the live scanner data.

## What it does

- pulls recent OSV ecosystem advisories for `npm`, `PyPI`, and `Go`
- filters to advisories published in the last 24 hours
- keeps only `HIGH` and `CRITICAL` candidates
- skips package versions already present in [`pkg/analyzer/data/blacklist.json`](/Users/brian93512/projects/tooltrust-scanner/pkg/analyzer/data/blacklist.json)
- opens one review PR with candidate blacklist entries

The workflow never auto-merges. A human still decides whether a candidate belongs in the enforced blacklist.

## Why this exists

Our blacklist is strong once an entry exists, but hand-editing it means we can lag major supply-chain events by hours. This pipeline narrows that gap by surfacing review-ready candidates quickly after OSV publishes an advisory.

## Review checklist

When the workflow opens a PR:

1. confirm the affected versions are exact and narrow enough
2. confirm `BLOCK` is the correct action
3. rewrite the reason if the current summary is too vague for triage
4. close the PR if the advisory is too broad, too noisy, or otherwise not suitable for blacklist enforcement

## Local dry run

```bash
go run ./scripts/ioc-candidates \
  -since 720h \
  -min-severity HIGH \
  -ecosystems npm,PyPI,Go \
  -out /tmp/candidates.json \
  -existing pkg/analyzer/data/blacklist.json
```

That gives us a 30-day sample so we can inspect candidate quality before relying on the scheduled workflow.

## Failure behavior

- transient OSV fetch failures log a warning and produce an empty candidate set
- the workflow does not fail `main` because an upstream feed had a bad day
- a no-op day simply means no PR is opened

## Scope

This is intentionally narrow:

- it only proposes additions to the blacklist
- it does not auto-remove entries
- it does not cover pre-advisory blog posts or social-media disclosures
- it does not replace the existing threat-intel issue workflow

Those are follow-ups once candidate quality is stable.
