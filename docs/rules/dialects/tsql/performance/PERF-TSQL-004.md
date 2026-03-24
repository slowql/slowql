# WAITFOR DELAY in Production Code (PERF-TSQL-004)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
WAITFOR DELAY ties up a connection and worker thread for the specified duration. An attacker can use it to confirm blind SQL injection or exhaust the connection pool.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
