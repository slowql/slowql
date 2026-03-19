# RAISE NOTICE Log Injection (SEC-PG-003)

**Dimension**: Security
**Severity**: Medium
**Scope**: Dialect Specific (Postgresql)

## Description
Log injection allows attackers to forge log entries.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use RAISE NOTICE 'message: %', variable instead of concatenation.
