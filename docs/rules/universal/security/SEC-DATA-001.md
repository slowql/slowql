# Data Exfiltration via File Operations (SEC-DATA-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Attackers can export entire tables to attacker-readable locations, read sensitive OS files (e.g., /etc/passwd, configuration files), or execute arbitrary OS commands via COPY PROGRAM.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Restrict FILE privilege in MySQL. Disable LOAD DATA INFILE via local_infile=0. Revoke COPY permissions in PostgreSQL. Use application-level export mechanisms with proper access controls instead of SQL-level file operations.
