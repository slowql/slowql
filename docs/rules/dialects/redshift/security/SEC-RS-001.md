# COPY With Embedded Credentials (SEC-RS-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Redshift)

## Description
AWS credentials in SQL appear in pg_stat_activity, query logs, STL_QUERYTEXT, and any monitoring tool. Anyone with log access can steal the credentials.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
