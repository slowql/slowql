# Duplicate WHERE Condition (QUAL-DRY-001)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Duplicate conditions waste parser cycles and obscure intent. They often indicate a copy-paste error where the second condition should have been different (e.g., OR instead of AND, or a different value).

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove the duplicate condition. If both conditions were intended to filter on different values, verify the logic — AND with two equal conditions on the same column always reduces to a single condition.
