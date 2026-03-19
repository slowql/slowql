# MySQL utf8 Instead of utf8mb4 (REL-MYSQL-003)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Dialect Specific (Mysql)

## Description
Data containing 4-byte Unicode characters (emoji, some CJK, mathematical symbols) will be silently truncated or rejected, causing data loss.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace CHARACTER SET utf8 with CHARACTER SET utf8mb4 and COLLATE utf8_general_ci with COLLATE utf8mb4_general_ci (or utf8mb4_unicode_ci). Update connection charset settings.
