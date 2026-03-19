# SELECT FROM DUAL in Application SQL (QUAL-ORA-002)

**Dimension**: Quality
**Severity**: Info
**Scope**: Dialect Specific (Oracle)

## Description
SELECT 1 FROM DUAL is Oracle-specific legacy syntax for selecting constants. It works but is non-portable and signals Oracle-specific code that cannot be migrated to PostgreSQL, MySQL, or other databases without modification.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use SELECT 1 (no FROM clause) which works in most modern databases. Oracle 23c+ supports SELECT 1 without FROM DUAL.
