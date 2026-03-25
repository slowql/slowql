# MySQL utf8 Instead of utf8mb4 (REL-MYSQL-003)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Data containing 4-byte Unicode characters (emoji, some CJK, mathematical symbols) will be silently truncated or rejected, causing data loss.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
