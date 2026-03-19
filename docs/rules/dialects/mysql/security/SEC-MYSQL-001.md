# LOAD DATA LOCAL INFILE (SEC-MYSQL-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Mysql)

## Description
A rogue MySQL server can read any file the client has access to.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use LOAD DATA INFILE (server-side). Disable with --local-infile=0.
