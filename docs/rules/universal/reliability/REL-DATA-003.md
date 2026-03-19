# ALTER TABLE Without Backup Signal (REL-DATA-003)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
DROP COLUMN permanently destroys column data. MODIFY COLUMN can silently truncate data if the new type is narrower. RENAME COLUMN breaks all application queries referencing the old name.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always take a full backup before destructive ALTER operations. Use expand-contract pattern for zero-downtime schema changes: add new column, migrate data, update application, then drop old column. Test in staging first.
