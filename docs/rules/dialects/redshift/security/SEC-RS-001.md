# COPY With Embedded Credentials (SEC-RS-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Redshift)

## Description
AWS credentials in SQL appear in pg_stat_activity, query logs, STL_QUERYTEXT, and any monitoring tool. Anyone with log access can steal the credentials.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use IAM role-based authentication: COPY ... IAM_ROLE 'arn:aws:iam::role/name'. Never embed ACCESS_KEY_ID in SQL.
