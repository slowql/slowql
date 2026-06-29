# Pre-commit Hook

SlowQL integrates with the [pre-commit](https://pre-commit.com/) framework to block SQL issues before they enter your Git history.

## Setup

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/slowql/slowql
    rev: v2.0.0
    hooks:
      - id: slowql
```

install the hook:
```bash
pre-commit install
```

## Configuration

``` Yaml
repos:
  - repo: https://github.com/slowql/slowql
    rev: v2.0.0
    hooks:
      - id: slowql
        args:
          - --fail-on
          - high
          - --min-confidence
          - contextual
```

## What It Does

When you run `git commit`, pre-commit passes the staged SQL files to SlowQL. If any issues at or above the `--fail-on` threshold are found, the commit is rejected.

``` text
SlowQL.......................................................................Failed
- hook id: slowql
- exit code: 2

src/queries.sql
  HIGH SEC-INJ-001    45:1  Potential SQL injection: string concatenation

1 file | 3 queries | 12ms
```
Fix the issue and commit again.

## Run Against All Files
To run against the entire repository (not just staged files):
```bash
pre-commit run --all-files
```

## Autofix Limitation
The `--fix` flag works on single files only. If you want to apply autofixes, run it manually before committing:

``` bash
# Preview
slowql src/queries.sql --diff

# Apply
slowql src/queries.sql --fix
```

## Manual Hook (Without pre-commit Framework)
If you prefer a simple shell hook:

``` Bash
# .git/hooks/pre-commit
#!/bin/sh
slowql . --git-diff --fail-on high
if [ $? -ne 0 ]; then
  echo "SlowQL found issues. Fix them before committing."
  exit 1
fi
```

``` Bash
chmod +x .git/hooks/pre-commit
```