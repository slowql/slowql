# WAITFOR DELAY in Production Code (PERF-TSQL-004)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
WAITFOR DELAY ties up a connection and worker thread for the specified duration. An attacker can use it to confirm blind SQL injection or exhaust the connection pool.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove WAITFOR DELAY from production code. If used for polling, use Service Broker or Query Notification instead.
