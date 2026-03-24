# Orphan Record Risk (REL-FK-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
INSERTs without FK verification create orphan records when parent doesn't exist. If FK constraints are disabled or missing, data integrity is silently corrupted.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
