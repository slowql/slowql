# ON UPDATE CASCADE With Timestamp Column (REL-MYSQL-004)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Dialect Specific (Mysql)

## Description
Timestamp auto-update on parent row triggers CASCADE to all children.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Separate timestamp columns from foreign key relationships.
