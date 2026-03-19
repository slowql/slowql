# Orphan Record Risk (REL-FK-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
INSERTs without FK verification create orphan records when parent doesn't exist. If FK constraints are disabled or missing, data integrity is silently corrupted.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Ensure FK constraints exist in schema. Or verify parent: INSERT INTO orders (user_id) SELECT ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ?). Use deferred FK checks if needed.
