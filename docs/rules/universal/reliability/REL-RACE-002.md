# TOCTOU Pattern (REL-RACE-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
TOCTOU vulnerabilities allow race conditions: checking if row exists, then acting, leaves a gap where another transaction can change state. Common in user registration, inventory management.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use atomic operations: INSERT ... ON CONFLICT, MERGE, or INSERT ... WHERE NOT EXISTS as single statement. If IF is required, wrap in SERIALIZABLE transaction or use advisory locks.
