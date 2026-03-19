# ALTER TABLE DROP COLUMN (SQLite Limitation) (REL-SQLITE-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Dialect Specific (Sqlite)

## Description
On SQLite < 3.35.0 this statement fails entirely. On 3.35+ it cannot drop primary key columns, unique columns, or columns referenced by indexes or foreign keys.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
For broad compatibility, use the 12-step ALTER TABLE process: CREATE new table, INSERT from old, DROP old, RENAME new. See https://www.sqlite.org/lang_altertable.html
