# Remote/Linked Data Access (SEC-DATA-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Attackers can use remote access functions to exfiltrate data to external servers, pivot to other databases in the network, or connect to attacker-controlled servers to stage further attacks.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Disable Ad Hoc Distributed Queries in SQL Server. Remove linked server connections that are not required. Restrict dblink extension usage in PostgreSQL. Use application-level integration instead of database-to-database direct connections.
