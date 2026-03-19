# pg_sleep Usage Detected (SEC-PG-001)

**Dimension**: Security
**Severity**: Medium
**Scope**: Dialect Specific (Postgresql)

## Description
pg_sleep() ties up a database connection for the specified duration. An attacker can use it to confirm blind SQL injection or exhaust the connection pool, causing denial of service.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove pg_sleep() calls from production code. If used for testing, guard behind a feature flag or test-only configuration.
