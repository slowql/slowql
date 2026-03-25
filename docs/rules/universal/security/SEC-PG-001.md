# pg_sleep Usage Detected (SEC-PG-001)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
pg_sleep() ties up a database connection for the specified duration. An attacker can use it to confirm blind SQL injection or exhaust the connection pool, causing denial of service.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
