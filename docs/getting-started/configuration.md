# Configuration

SlowQL's deeply typed configuration engine is designed to adapt to massive monorepos and enterprise architectures seamlessly.

The engine resolves settings linearly. When `slowql` executes, it aggregates configurations in the following strict hierarchy:
1. **Command Line Arguments** (Highest Priority)
2. **Environment Variables**
3. **Local Configuration Files**
4. **Internal Defaults** (Lowest Priority)

---

## File-Based Configuration

SlowQL automatically climbs your directory tree looking for any of the following files:
- `slowql.toml` or `slowql.yaml` (`.yml` / `.json` also supported)
- Hidden dotfile equivalents (e.g., `.slowql.toml`)
- The `[tool.slowql]` namespace inside `pyproject.toml`

### Generating a Starter Config
The fastest way to scaffold a configuration profile is by triggering the interactive assistant:
```bash
slowql --init
```

### The `slowql.yaml` Schema
SlowQL groups settings into six root objects mapping directly to core engine behaviors:

```yaml
# slowql.yaml
severity:
  fail_on: high
  warn_on: medium

output:
  format: console
  color: true
  show_snippets: true
  max_issues: 0                  # 0 = unlimited display
  group_by: severity             # groups by: severity, dimension, file, rule, none

analysis:
  dialect: postgresql            # Default AST Grammar
  parallel: true                 # Hardware multithreading
  max_workers: 0                 # Number of parallel workers (0 = auto)
  timeout_seconds: 30.0          # Bailout for excessively complex payloads
  max_query_length: 100000       # Prevent OOM parsing malicious squashes
  enabled_dimensions:
    - security
    - performance
    - reliability
  disabled_rules:                # Blacklist array
    - QUAL-STYLE-001             
  severity_overrides:            # Rule-specific level overrides
    PERF-SCAN-001: info
    QUAL-NULL-001: critical
  
schema:
  path: schemas/prod_schema.sql  # Enables schema validation queries (column limits)

compliance:
  frameworks:
    - pci-dss
    - gdpr
  strict_mode: true

cost:
  cloud_provider: snowflake
  compute_cost_per_hour: 4.50
  storage_cost_per_gb: 0.02
```

---

## Configuration Blocks Explained

### `severity`
Controls how pipeline exits handle found issues.
- **`fail_on`**: Crucial for CI/CD. The process returns an exit code `1` if the analysis discovers any vulnerability equal to or exceeding this threshold. Options: `critical`, `high`, `medium`, `low`, `info`, `never`.

### `output`
Governs terminal formatting.
- **`group_by`**: Re-slices the output array visually, highly useful for filtering (`severity`, `dimension`, `file`).

### `analysis`
Tunes the AST processor.
- **`timeout_seconds`**: Because SQL parsing can hit algorithmic cliffs (e.g. 5,000 deep `IN` arrays), SlowQL will dynamically drop a query block if it exceeds this threshold to save CI minutes.
- **`disabled_rules`**: A global blacklist for specific Rule IDs (e.g., `PERF-SCAN-001`) that your company doesn't care about enforcing.
- **`severity_overrides`**: Customize the severity of specific rules on a per-project basis.
  ```yaml
  analysis:
    severity_overrides:
      PERF-SCAN-001: info      # Downgrade to Info
      QUAL-NULL-001: critical  # Upgrade to Critical
  ```

### `compliance` & `cost`
Configures the environment bounds for dimensions that require external realities (like specific frameworks or pricing tiers) to calculate accurate diagnostics.

---

## Environment Variable Overrides

SlowQL supports native, deeply nested environment variables by reading the `SLOWQL_` prefix and utilizing the standard double-underscore `__` separator for nesting schema definitions.

This enables you to lock down the baseline config in Git via `slowql.yaml`, but override outputs dynamically in your CI runners:

```bash
# Force SARIF output despite what the YAML claims
export SLOWQL_OUTPUT__FORMAT=sarif

# Enforce strict parsing
export SLOWQL_ANALYSIS__DIALECT=snowflake

# Override cost parameters dynamically (e.g., in a cloud-specific runner)
export SLOWQL_COST__COMPUTE_COST_PER_HOUR=2.50

slowql src/
```

This flexibility prevents pipeline configurations from bleeding into developer local setups.
