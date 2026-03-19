# Implicit Foreign Key (Logic) (QUAL-SCHEMA-002)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Missing foreign keys lead to orphaned records and data corruption. Referenced data can be deleted without cleaning up dependent rows, breaking application logic.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add FOREIGN KEY ... REFERENCES ... constraints. This ensures referential integrity at the database level.
