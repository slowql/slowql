# SELECT FROM DUAL in Application SQL (QUAL-ORA-002)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
SELECT 1 FROM DUAL is Oracle-specific legacy syntax for selecting constants. It works but is non-portable and signals Oracle-specific code that cannot be migrated to PostgreSQL, MySQL, or other databases without modification.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
