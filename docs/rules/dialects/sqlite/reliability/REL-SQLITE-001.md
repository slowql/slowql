# ALTER TABLE DROP COLUMN (SQLite Limitation) (REL-SQLITE-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Dialect Specific (Sqlite)

## Description
On SQLite < 3.35.0 this statement fails entirely. On 3.35+ it cannot drop primary key columns, unique columns, or columns referenced by indexes or foreign keys.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
