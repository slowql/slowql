# Consider WAL Mode for Concurrent Access (PERF-SQLITE-001)

**Dimension**: Performance
**Severity**: Info
**Scope**: Dialect Specific (Sqlite)

## Description
Without WAL mode, any write operation locks the entire database file, blocking all concurrent readers and writers.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Set PRAGMA journal_mode=WAL for concurrent read/write access. Note: WAL mode is persistent and only needs to be set once.
