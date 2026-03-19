# MyISAM Engine Usage (REL-MYSQL-005)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Dialect Specific (Mysql)

## Description
MyISAM tables can be corrupted by crashes, power failures, or killed queries. There is no automatic recovery — manual REPAIR TABLE is required and may lose data.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use ENGINE=InnoDB. Convert existing tables: ALTER TABLE t ENGINE=InnoDB.
