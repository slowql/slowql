# TOCTOU Pattern (REL-RACE-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
TOCTOU vulnerabilities allow race conditions: checking if row exists, then acting, leaves a gap where another transaction can change state. Common in user registration, inventory management.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
