# CREATE INDEX Without CONCURRENTLY (REL-PG-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Postgresql)

## Description
On large tables, CREATE INDEX can lock writes for minutes.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use CREATE INDEX CONCURRENTLY. Note: cannot run inside a transaction block.
