# ALTER TABLE MOVE Without REBUILD INDEX (REL-ORA-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Oracle)

## Description
After MOVE, all indexes become UNUSABLE — queries error or fall back to full scans.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Follow ALTER TABLE MOVE with ALTER INDEX ... REBUILD for every index.
