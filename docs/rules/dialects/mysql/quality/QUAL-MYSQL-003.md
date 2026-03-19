# Deprecated LOCK IN SHARE MODE (QUAL-MYSQL-003)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Mysql)

## Description
Code using LOCK IN SHARE MODE will break when the syntax is removed in a future MySQL version.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace LOCK IN SHARE MODE with FOR SHARE (MySQL 8.0+).
