# AUTOINCREMENT Overhead in SQLite (QUAL-SQLITE-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Sqlite)

## Description
AUTOINCREMENT prevents rowid reuse and requires extra reads/writes to the sqlite_sequence table on every INSERT.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use INTEGER PRIMARY KEY without AUTOINCREMENT. SQLite guarantees unique monotonically increasing rowids without it. AUTOINCREMENT only guarantees never-reused IDs, which is rarely needed.
