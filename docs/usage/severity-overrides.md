# Severity Overrides

Override the severity of any rule in your configuration file.

## Configuration

```yaml
analysis:
  severity_overrides:
    PERF-SCAN-001: info      # Downgrade SELECT * to informational
    QUAL-NULL-001: critical  # Upgrade null comparison to critical
    SEC-INJ-001: high        # Keep injection at high
```

## Valid Severity Values

`critical`, `high`, `medium`, `low`, `info`

## How It Works

Overrides are applied after all rules execute and before results are reported. The modified severity is used for:

- Display in console output
- `--fail-on` threshold evaluation
- Export to JSON, SARIF, HTML

## Examples

### Downgrade for Legacy Codebases
``` YAML
analysis:
  severity_overrides:
    PERF-SCAN-001: info   # SELECT * is common in this legacy project
    PERF-SCAN-003: low    # Unbounded SELECT is acceptable here
```

### Upgrade for Security-Critical Projects
``` YAML
analysis:
  severity_overrides:
    QUAL-NULL-001: critical  # Null comparison errors must be blocking
    SEC-AUTH-002: high       # Grant to PUBLIC must be visible
```

## Interaction with Other Feattures

- **Inline suppression**: If a rule is suppressed via comment directive, the override is never applied.
- **Disabled rules**: If a rule is in `disabled_rules`, overrides for it are ignored.
- **Baseline mode**: New issues are reported with the overridden severity.
- **Confidence levels**: Overrides apply regardless of confidence level.