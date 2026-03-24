# ALTER TABLE Without Backup Signal (REL-DATA-003)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
DROP COLUMN permanently destroys column data. MODIFY COLUMN can silently truncate data if the new type is narrower. RENAME COLUMN breaks all application queries referencing the old name.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
