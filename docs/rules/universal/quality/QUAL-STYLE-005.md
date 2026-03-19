# INSERT Without Column List (QUAL-STYLE-005)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
A schema change (ALTER TABLE ADD COLUMN) silently shifts all values one position, causing data corruption without any error.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always specify columns: INSERT INTO table (col1, col2) VALUES (v1, v2).
