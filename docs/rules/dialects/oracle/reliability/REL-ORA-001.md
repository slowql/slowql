# CONNECT BY Without NOCYCLE (REL-ORA-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Oracle)

## Description
A cyclic reference in hierarchical data causes CONNECT BY to loop indefinitely, consuming CPU and memory until the session is killed or the server runs out of resources.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add NOCYCLE keyword: CONNECT BY NOCYCLE PRIOR parent_id = id. Use CONNECT_BY_ISCYCLE pseudo-column to detect and handle cycles.
