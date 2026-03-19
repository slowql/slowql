# FLATTEN Without Explicit Path (QUAL-SF-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Snowflake)

## Description
Without explicit path, FLATTEN depends on column position which can silently produce wrong results after schema changes.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use explicit parameters: LATERAL FLATTEN(input => col, path => 'key').
