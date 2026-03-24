# Severity Overrides

Severity Overrides allow you to customize the severity level of any SlowQL rule on a per-project basis. This is useful when your team's standards differ from the SlowQL defaults, or when you want to elevate specific quality rules to critical status or downgrade performance warnings to info.

---

## Configuration

Overrides are defined in the `analysis` section of your `slowql.yaml` (or other supported configuration files) under the `severity_overrides` key.

```yaml
analysis:
  severity_overrides:
    PERF-SCAN-001: info      # Downgrade "SELECT *" to Info
    QUAL-NULL-001: critical  # Upgrade "WHERE x = NULL" to Critical
    SEC-INJ-001: high        # Ensure a specific security rule is High
```

### Supported Severity Levels

The following severity levels can be used as target values:
- `critical`
- `high`
- `medium`
- `low`
- `info`

---

## How it Works

The SlowQL engine applies overrides at the end of the analysis phase, just before issues are reported or filtered. 

1. **Standard Analysis:** All rules execute with their built-in default severities.
2. **Override Application:** If a rule ID matches a key in your `severity_overrides` configuration, the engine replaces the issue's severity with your configured value.
3. **Filtering & Exiting:** The modified severities are then used to determine if an issue should cause a pipeline failure (via `fail_on`) or a warning (via `warn_on`).

> [!NOTE]
> Overrides are applied to all instances of a rule. If you want to suppress a specific instance of a rule on a single line, use [Inline Suppression](suppression.md) instead.

---

## Examples

### Downgrading for Legacy Projects
If you are working on a legacy project where `SELECT *` is prevalent and you don't want it to clutter your "Medium" or "High" reports, you can downgrade it:

```yaml
analysis:
  severity_overrides:
    PERF-SCAN-001: info
```

### Upgrading for High-Security Environments
If your project handles sensitive data and you want to ensure that any potential null pointer or type mismatch in a critical path is treated as a blocker:

```yaml
analysis:
  severity_overrides:
    QUAL-NULL-001: critical
```

---

## Interaction with Other Features

### Inline Suppression
If a rule is suppressed via an inline comment (e.g., `-- slowql-disable-line`), the severity override is never applied because the issue is discarded before the override phase.

### Global Disabling
If a rule is listed in `disabled_rules`, it will never fire, and any corresponding entry in `severity_overrides` will be ignored.

### Baseline Mode
Severity overrides apply to new issues found while running in baseline mode. If a new issue matches an overridden rule, it will be reported with the new severity.
