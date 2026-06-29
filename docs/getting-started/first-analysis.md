# First Analysis

## Scan a SQL File

``` bash
slowql queries.sql
```
SlowQL runs in **proven mode** by default. Only structurally verified findings are shown. Zero false positives.

## Scan a Directory
``` bash
slowql src/
```
SlowQL walks the directory recursively, finds all supported files, classifies each file by context, and runs appropriate rules.

## Read the Output
``` text
[proven mode] Only structurally verified findings shown.

SlowQL v2.0.0 - 142 queries scanned, 3 issues found

  CRITICAL: 1
      HIGH: 2

  src/api.py
    CRITICAL SEC-INJ-001    45:12  Potential SQL injection: string concatenation with variable
               > "SELECT * FROM users WHERE id = " + user_id
               https://slowql.dev/rules/sec-inj-001

    HIGH PERF-SCAN-002      89:1   Unbounded DELETE detected (missing WHERE).
               > DELETE FROM sessions
               https://slowql.dev/rules/perf-scan-002

  src/reports.sql
    HIGH REL-DATA-001       12:1   CRITICAL: DELETE statement has no WHERE clause.
               > DELETE FROM audit_log
               https://slowql.dev/rules/rel-data-001

  3 files | 142 queries | 287ms | 495 queries/sec
```

## Severity Levels

| **Severity** | **Meaning** |
|----------|---------|
| **critical** | Data loss, active injection vectors, catastrophic risk |
| **high** | Severe structural flaws, security vulnerabilities |
| **medium** | Suboptimal patterns, technical debt |
| **low** | Style issues, minor optimizations |
| **info** | Informational only |


## Exit Codes

| **Code** | **Meaning** |
|----------|---------|
| **0** | No issues found or issues below threshold |
| **1** | Issues found at medium or low severity |
| **2** | Issues found at high severity |
| **3** | Issues found at critical severity |

## Show More Findings
``` bash
# Add context-dependent findings (for code review)
slowql src/ --min-confidence contextual

# Add all hints and style suggestions
slowql src/ --min-confidence advisory
```

## Export Results
``` bash
# Export to JSON
slowql src/ --export json --out reports/

# Export to multiple formats
slowql src/ --export json --export html --export sarif --out reports/
```

## Next Steps

- [Configuration](/docs/getting-started/configuration.md) - Set dialect, disabled rules, fail-on threshold
- [CLI Reference](/docs/getting-started/cli-reference.md) - Full flag reference
- [CI/CD Integration](/docs/getting-started/ci-cd-integration.md) - Use in pipelines