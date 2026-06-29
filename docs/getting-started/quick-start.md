# Quick Start

## Scan a Directory

```bash
slowql src/
```
By default, SlowQL runs in **proven mode**: only structurally verified findings with zero false positives.

## Scan a Single File

``` Bash
slowql queries.sql
```

## Scan with Schema Validation

``` Bash
slowql src/ --schema db/schema.sql
```

## Show More Findings
``` Bash
# Context-dependent findings (for code review)
slowql src/ --min-confidence contextual

# All findings including hints (for comprehensive audit)
slowql src/ --min-confidence advisory
```

## CI Mode
``` Bash
slowql src/ --fail-on high --format github-actions
```

## Explore Rules
``` Bash
slowql --list-rules
slowql --list-rules --filter-dimension security
slowql --explain SEC-INJ-001
```

## Generate Config
``` Bash
slowql --init
```
This creates a `slowql.yaml` with sensible defaults.
