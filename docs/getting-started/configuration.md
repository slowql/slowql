# Configuration

SlowQL discovers configuration from these files (in order):

1. `slowql.yaml` or `.slowql.yaml`
2. `slowql.toml` or `.slowql.toml`
3. `pyproject.toml` (under `[tool.slowql]`)

Configuration is searched in the analyzed directory and all parent directories.

## Example Configuration

```yaml
analysis:
  dialect: postgresql
  enabled_dimensions:
    - security
    - performance
    - reliability
    - cost
    - quality
  disabled_rules: []
  min_confidence: proven
  # custom_rules: .slowql-rules.yaml

severity:
  fail_on: high

# compliance:
#   frameworks:
#     - gdpr
#     - pci-dss

# schema:
#   path: db/schema.sql

# complexity:
#   threshold_optimal: 40
#   threshold_complex: 70
```

## Generate Config
``` Bash
slowql --init
slowql --init --dialect mysql
```

## Key Settings

`analysis.dialect`
SQL dialect for parsing. Auto-detected if not set.

`analysis.min_confidence`
Default confidence level. Options: `proven` (default), `contextual`, `advisory`.

`analysis.disabled_rules`
List of rule IDs to skip. Supports exact IDs and prefixes.
``` YAML
analysis:
  disabled_rules:
    - PERF-SCAN-001
    - QUAL-STYLE
```

`analysis.severity_overrides`
Override severity for specific rules.
```yaml
analysis:
  severity_overrides:
    QUAL-NULL-001: critical
    PERF-SCAN-001: info
```

`severity.fail_on`
Exit with non-zero code when issues at or above this severity are found. Used in CI.

`compliance.frameworks`
Enable compliance rules for specific frameworks. Without this, compliance rules are skipped.

``` YAML
compliance:
  frameworks:
    - gdpr
    - hipaa
    - pci-dss
```

`analysis.custom_rules`
Path to a YAML file containing custom rules.
``` YAML
analysis:
  custom_rules: .slowql-rules.yaml
```

`analysis.table_metadata`
Provide metadata about tables for more accurate analysis.
``` YAML
analysis:
  table_metadata:
    large_tables:
      - events
      - logs
    partitioned_tables:
      events:
        - created_at
```
