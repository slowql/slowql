# Missing Index on Foreign Key (QUAL-SCHEMA-003)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
JOINs and CASCADE deletes on unindexed foreign keys are extremely slow. They cause full table scans for every referenced record lookup, killing performance.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
