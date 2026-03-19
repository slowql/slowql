# OS Command Injection (PostgreSQL) (SEC-CMD-001-PG)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Postgresql)

## Description
pg_read_file and pg_execute_server_program allow reading arbitrary files and executing OS commands. Requires superuser — indicates privilege abuse.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Revoke superuser from application accounts. Never call pg_execute_server_program from application SQL. Use application-layer file operations instead.
