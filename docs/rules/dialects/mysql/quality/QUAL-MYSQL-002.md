# STRAIGHT_JOIN Hint (QUAL-MYSQL-002)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Mysql)

## Description
Forced join order may become suboptimal as data distribution changes.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove STRAIGHT_JOIN. Update statistics with ANALYZE TABLE.
