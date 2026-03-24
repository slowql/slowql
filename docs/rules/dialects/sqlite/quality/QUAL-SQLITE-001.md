# AUTOINCREMENT Overhead in SQLite (QUAL-SQLITE-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Sqlite)

## Description
AUTOINCREMENT prevents rowid reuse and requires extra reads/writes to the sqlite_sequence table on every INSERT.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
