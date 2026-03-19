# ATTACH DATABASE Arbitrary File Access (SEC-SQLITE-001)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Sqlite)

## Description
An attacker can read any file as a SQLite database or create new files. Combined with writeable paths, this enables code execution via crafted database files.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Never allow user input in ATTACH DATABASE paths. Use sqlite3_limit(SQLITE_LIMIT_ATTACHED) to restrict. Consider SQLITE_DBCONFIG_ENABLE_ATTACH to disable entirely.
