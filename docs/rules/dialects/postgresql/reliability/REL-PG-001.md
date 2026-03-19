# ALTER TABLE ADD COLUMN With Volatile DEFAULT (REL-PG-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Postgresql)

## Description
A table rewrite on a large table locks it exclusively.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add column as NULLable first, backfill in batches, then add NOT NULL.
