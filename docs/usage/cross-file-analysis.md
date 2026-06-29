# Cross-File Analysis

SlowQL performs project-level analysis after individual file analysis to detect issues that span multiple files.

## What It Detects

### Duplicate Queries

Queries with identical normalized SQL appearing in multiple files. Useful for identifying consolidation opportunities.

Rule: `QUAL-DEAD-003`

### Unused Database Objects

Views, functions, and procedures that are defined but never referenced anywhere in the project.

Rule: `QUAL-DEAD-001`

### Breaking DDL Changes

When a `DROP TABLE` or `DROP COLUMN` in one file would break a query in another file.

Rule: `SCH-BRK-001`

## Triggering Cross-File Analysis

Cross-file analysis runs automatically when you scan a directory:

``` Bash
slowql src/
```

## Performance

Cross-file analysis uses O(Q) indexed lookups (HashMap) rather than nested scans. For repositories with more than 20,000 queries, project-level analysis is skipped automatically since cross-file analysis is only meaningful for focused application codebases.

## Confidence
Cross-file findings are `contextual` confidence, not proven. They appear with `--min-confidence` contextual:
``` Bash
slowql src/ --min-confidence contextual
```

## Suppression
Cross-file findings can be suppressed using inline directives:
``` SQL
DROP TABLE users;  -- slowql-disable-line SCH-BRK-001
```

Or disable globally:
``` YAML
analysis:
  disabled_rules:
    - QUAL-DEAD-003
```
