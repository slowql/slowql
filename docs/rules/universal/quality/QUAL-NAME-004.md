# Reserved Word as Identifier (QUAL-NAME-004)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Using reserved words forces the use of double quotes and can lead to syntax errors if quotes are missing. It also makes queries much harder to read.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Choose a non-reserved synonym. Use 'created_at' instead of 'DATE', 'sort_order' instead of 'ORDER', 'user_account' instead of 'USER'.
