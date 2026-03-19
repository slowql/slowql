# INSERT IGNORE Silences Errors (REL-MYSQL-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Mysql)

## Description
INSERT IGNORE silently discards duplicate key errors, data truncation warnings, and constraint violations. Failed inserts are invisible — data loss goes undetected.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use INSERT ... ON DUPLICATE KEY UPDATE for intentional upserts. Use explicit duplicate checking for insert-only logic. Never use INSERT IGNORE where data integrity matters.
