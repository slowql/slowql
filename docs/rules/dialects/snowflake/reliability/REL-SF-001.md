# COPY INTO Without ON_ERROR (REL-SF-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Snowflake)

## Description
A single malformed row aborts the entire load.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add ON_ERROR = 'CONTINUE' or 'SKIP_FILE'. Use VALIDATION_MODE for rejected rows.
