# COPY INTO With Embedded Credentials (SEC-SF-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Snowflake)

## Description
Cloud credentials appear in QUERY_HISTORY, INFORMATION_SCHEMA, and Snowflake audit logs. Any user with MONITOR privilege can see them.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use storage integrations: CREATE STORAGE INTEGRATION ... Then reference: COPY INTO ... FROM @stage. Never embed keys in SQL.
