# COPY INTO Without Explicit File Format (COST-SF-002)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Dialect Specific (Snowflake)

## Description
COPY INTO without FILE_FORMAT relies on default or stage-level format settings. If defaults change or the stage is reconfigured, data loading silently fails or loads malformed data without error.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
