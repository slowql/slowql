# FORCE INDEX / USE INDEX Hint (PERF-MYSQL-003)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Mysql)

## Description
Forced indexes bypass the optimizer and may force worse plans over time.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove index hints. Update statistics with ANALYZE TABLE instead.
