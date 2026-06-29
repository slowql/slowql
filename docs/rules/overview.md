
# Rule Overview

SlowQL ships with 282+ rules across six dimensions.

## Dimensions

| Dimension | Rules | Description |
|-----------|------:|-------------|
| Security | 61 | SQL injection, privilege escalation, credential exposure, SSRF, data exfiltration |
| Performance | 73 | Full scans, indexing, joins, locking, sorting, pagination, batching |
| Reliability | 44 | Data loss prevention, transactions, race conditions, idempotency |
| Quality | 52 | Naming, complexity, null handling, style, dead code, schema design |
| Cost | 33 | Cloud warehouse optimization, storage, compute, network, partitioning |
| Compliance | 18 | GDPR, HIPAA, PCI-DSS, SOX, CCPA |

## Confidence Levels

Every rule has a confidence level:

| Level | Meaning | Use case |
|-------|---------|----------|
| **Proven** | Structurally deterministic. Zero false positives. | CI gates, automated enforcement |
| **Contextual** | Accurate with context. May need verification. | Code review, security audit |
| **Advisory** | Style hint or best practice. | Comprehensive audit, onboarding |

## Dialect Coverage

107 rules are dialect-specific. 175 rules fire on all dialects.

| Dialect | Specific Rules |
|---------|---------------:|
| PostgreSQL | 12 |
| MySQL | 15 |
| T-SQL | 23 |
| Oracle | 11 |
| Snowflake | 9 |
| BigQuery | 6 |
| SQLite | 6 |
| Redshift | 7 |
| ClickHouse | 7 |
| DuckDB | 3 |
| Presto/Trino | 4 |
| Spark/Databricks | 5 |

## Exploring Rules

```bash
# List all rules
slowql --list-rules

# Filter by dimension
slowql --list-rules --filter-dimension security

# Filter by dialect
slowql --list-rules --filter-dialect postgresql

# Explain a specific rule
slowql --explain SEC-INJ-001
```

## Custom Rules
Define organization-specific rules in YAML:
``` YAML
rules:
  - id: ORG-001
    name: "Require tenant_id filter"
    severity: high
    dimension: security
    pattern: "SELECT.*FROM\\s+orders\\b(?!.*tenant_id)"
    message: "All queries on orders table must filter by tenant_id"
```

Load via config:
``` YAML
analysis:
  custom_rules: .slowql-rules.yaml
```


