# SlowQL
Catch expensive SQL before it hits production.  
Static, offline SQL analyzer that prevents performance regressions, security risks, correctness bugs, and cloud‑cost traps — with a polished terminal experience.

[![Release](https://img.shields.io/github/v/release/makroumi/slowql?logo=github&label=v1.0.3)](https://github.com/makroumi/slowql/releases) [![PyPI](https://img.shields.io/pypi/v/slowql?logo=pypi)](https://pypi.org/project/slowql/) [![Docker](https://img.shields.io/docker/v/makroumi/slowql?logo=docker&label=docker)](https://hub.docker.com/r/makroumi/slowql) [![GHCR](https://img.shields.io/badge/GHCR-slowql-blue?logo=github)](https://github.com/makroumi/slowql/pkgs/container/slowql) [![Docker Pulls](https://img.shields.io/docker/pulls/makroumi/slowql?logo=docker&label=pulls)](https://hub.docker.com/r/makroumi/slowql) [![PyPI Downloads](https://img.shields.io/badge/PyPI%20downloads-~1200%2Fmonth-blue?logo=pypi)](https://pypistats.org/packages/slowql) [![GitHub stars](https://img.shields.io/github/stars/makroumi/slowql?style=social&logo=github)](https://github.com/makroumi/slowql/stargazers) [![CI](https://github.com/makroumi/slowql/actions/workflows/ci.yml/badge.svg?logo=github)](https://github.com/makroumi/slowql/actions) [![Coverage](https://codecov.io/gh/makroumi/slowql/branch/main/graph/badge.svg?logo=codecov)](https://codecov.io/gh/makroumi/slowql) [![Ruff](https://img.shields.io/badge/linter-ruff-blue?logo=python)](https://github.com/charliermarsh/ruff) [![Mypy](https://img.shields.io/badge/type_check-mypy-blue?logo=python)](http://mypy-lang.org/) [![Tests](https://img.shields.io/badge/test_suite-pytest-blue?logo=pytest)](https://docs.pytest.org/) [![Dependabot](https://img.shields.io/badge/dependabot-enabled-brightgreen?logo=dependabot)](https://github.com/makroumi/slowql/security/dependabot) [![Security](https://img.shields.io/badge/security-scanned%20via%20Snyk-blue?logo=snyk)](https://snyk.io/test/github/makroumi/slowql) [![Discussions](https://img.shields.io/github/discussions/makroumi/slowql?logo=github)](https://github.com/makroumi/slowql/discussions) [![Contributors](https://img.shields.io/github/contributors/makroumi/slowql?logo=github)](https://github.com/makroumi/slowql/graphs/contributors) [![Sponsor](https://img.shields.io/github/sponsors/makroumi?logo=github)](https://github.com/sponsors/makroumi)

![SlowQL Demo](assets/demo.gif)

## Table of Contents
- [Overview](#overview)
- [Why teams adopt SlowQL](#why-teams-adopt-slowql)
- [Key features](#key-features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Keyboard navigation](#keyboard-navigation)
- [Exports](#exports)
- [Rule coverage (examples)](#rule-coverage-examples)
- [How it works](#how-it-works)
- [Integrations (CI / pre-commit / Docker)](#integrations-ci--pre-commit--docker)
- [Performance & privacy](#performance--privacy)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [FAQ](#faq)

## Overview
SlowQL is a static SQL analyzer and linter for performance, security, cost, and correctness. It scans SQL text to catch issues early — no database connection required — and presents the results in a premium, modern terminal dashboard.  
Designed for data engineering and product teams shipping SQL daily on PostgreSQL, MySQL, SQLite, SQL Server, Snowflake, BigQuery, Redshift (pattern coverage varies by rule).

## Why teams adopt SlowQL
- Reduce cloud costs by preventing full-table scans, deep OFFSET pagination, and heavy JSON work.
- Prevent disasters by blocking `UPDATE/DELETE` without `WHERE`.
- Shorten reviews with deterministic guidance and actionable fixes.
- Keep environments safe by detecting dynamic SQL concatenation, plaintext secrets, and PII exposure patterns.
- Produce credible, shareable HTML/CSV/JSON reports for leadership and CI/CD.

## Key features
- Broad rule catalog across PERFORMANCE, COST, SECURITY, CORRECTNESS, RELIABILITY, QUALITY.
- Health score (0–100), severity distribution, and impact zones.
- Premium terminal dashboard:
  - Health gauge
  - Severity × Dimension heat map
  - System detection capabilities (rules per dimension vs findings)
  - Issue frequency spectrum
  - Detailed issues table with real Impact & Fix
  - Recommended action protocols generated from actual fixes
- Arrow-key menus (↑/↓ + Enter, q/Esc) for:
  - Input mode (Compose | Paste | File | Compare)
  - Quick actions (Export | Analyze more | Exit)
  - Export selection (JSON | HTML | CSV | All)
- Exports: JSON (machine-readable), HTML (neon single page), CSV (flat rows)
- Non-interactive CI mode for pipelines

## Installation
Python 3.9+

Recommended:
```bash
pipx install slowql
```

Standard:
```bash
pip install slowql
```

Optional for arrow-key menus:
```bash
pip install readchar
```

## Quick start
Analyze a file:
```bash
slowql --input-file queries.sql
```

Export immediately:
```bash
slowql --input-file queries.sql --export html csv
```

Compose or paste (arrow‑key menus appear when `--mode=auto` in a TTY):
```bash
slowql --mode auto
```

Compare two queries:
```bash
slowql --compare
```

Non‑interactive (CI):
```bash
slowql --non-interactive --input-file queries.sql --export json
```

## CLI usage
```text
usage: slowql [-h] [--input-file INPUT_FILE] [--mode {auto,paste,compose}] [--no-cache] [--compare]
              [--export [{html,csv,json} ...]] [--out OUT] [--verbose] [--no-intro] [--fast]
              [--duration DURATION] [--non-interactive]
              [file]

Input Options:
  file                             Input SQL file (optional positional)
  --input-file                     Read SQL from file
  --mode {auto,paste,compose}      Editor mode (auto chooses compose on TTY)

Analysis Options:
  --no-cache                       Disable query result caching
  --compare                        Enable query comparison mode

Output Options:
  --export [{html,csv,json} ...]   Auto-export formats after each analysis
  --out OUT                        Output directory for exports
  --verbose                        Enable verbose analyzer output

UI Options:
  --no-intro                       Skip intro animation
  --fast                           Fast mode: minimal animations
  --duration DURATION              Intro animation duration (seconds)
  --non-interactive                Non-interactive mode for CI/CD
```

## Keyboard navigation
- Menus: ↑/↓ to move, Enter to select, q/Esc to cancel
- Quick Actions: Export Report | Analyze More | Exit
- Export Options: JSON | HTML | CSV | All
- Input Mode (auto): Compose | Paste | File | Compare | Cancel  
If `readchar` isn’t available or the terminal isn’t interactive, menus fall back to a numeric prompt.

## Exports
- JSON: full machine‑readable payload  
- HTML: shareable, dark neon single‑page report  
- CSV: `severity,rule_id,dimension,message,impact,fix,location`

Write exports automatically with `--export`:
```bash
slowql --input-file queries.sql --export html csv
```
Or choose formats via the arrow‑key Export menu. Reports are written to `./reports` by default (customize with `--out`).

## Rule coverage (examples)
Security:
- Dynamic SQL / concatenation
- Excessive grants and wildcard principals
- Hardcoded secrets / API keys
- PII exposure patterns (emails, SSNs)

Performance:
- `SELECT *`
- Non‑SARGable predicates (functions on columns, leading wildcard LIKE)
- Deep OFFSET pagination
- Regex in WHERE; heavy JSON extraction

Cost:
- Unbounded scans on partitioned data
- Unfiltered aggregation
- Cross‑region joins (where detectable)

Correctness / Logic:
- `UPDATE/DELETE` without `WHERE`
- NULL comparison bugs (`= NULL` / `!= NULL`)
- Always true/false conditions

Reliability:
- Window functions without `PARTITION BY`
- Recursive CTE without bounds

Quality / Maintainability:
- Unused CTE
- Excess `DISTINCT`
- Identifier/style consistency (optional)

The catalog is large and expanding; see code and docs for the current list.

## How it works
- Static analysis: no connection to your database.
- Deterministic: parses SQL text and applies rule signatures, heuristics, and structural checks.
- Multi‑query awareness: detects duplicate patterns and N+1 shapes across batches.
- Privacy‑first: your SQL never leaves your machine.

## Integrations (CI / pre-commit / Docker)

GitHub Actions:
```yaml
name: SlowQL
on: [push, pull_request]
jobs:
  lint-sql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install slowql readchar
      - run: slowql --non-interactive --input-file sql/ --export json
      - name: Fail on critical issues
        run: |
          python - <<'PY'
          import json, glob
          path = sorted(glob.glob('reports/slowql_results_*.json'))[-1]
          data = json.load(open(path, encoding='utf-8'))
          critical = data["statistics"]["by_severity"].get("CRITICAL", 0)
          if critical > 0:
              raise SystemExit(f"Found {critical} CRITICAL issues")
          PY
```

Pre‑commit (conceptual):
```yaml
repos:
  - repo: local
    hooks:
      - id: slowql
        name: SlowQL
        entry: slowql --non-interactive --export json
        language: system
        files: \.sql$
```

Docker:
```bash
docker run --rm -v "$PWD":/work makroumi/slowql slowql --input-file /work/queries.sql --export html
```

## Performance & privacy
- Static analysis; no DB round‑trips.
- Precompiled signatures; fast heuristics.
- Offline by default; zero telemetry.
- Nothing leaves your machine unless you export files.

## Roadmap
- Issue browser (arrow keys; expand details)
- Multi‑select export (space toggles, Enter confirms)
- VS Code extension
- Dialect‑specific packs & AST expansion
- Pluggable rule packs and org policies
- Browser playground (Pyodide)

## Contributing
We welcome PRs for new rules, docs, tests, and formatters.

Dev setup:
```bash
git clone https://github.com/makroumi/slowql
cd slowql
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
ruff check .
mypy .
```

Before opening a PR:
- Include tests for new rules
- Update docs and examples
- Ensure `ruff` and `mypy` pass

## License
Apache 2.0 — see [LICENSE](LICENSE)

## FAQ
**Does SlowQL connect to my database?**  
No. It analyzes SQL text only.

**Which dialects are supported?**  
Rules are mostly dialect‑agnostic (PostgreSQL, MySQL, SQLite, SQL Server, Snowflake, BigQuery, Redshift). Dialect‑specific packs are planned.

**How many rules are there?**  
A large and growing catalog across performance, security, cost, logic, reliability, and style.

**Can I write custom rules?**  
Yes — the detector architecture is modular. Public API and examples are planned.
