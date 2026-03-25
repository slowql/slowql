# SELECT * Usage (PERF-SCAN-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description


**Rationale:**
SELECT * retrieves all columns from a table, which often includes large text fields or unneeded metadata. This increases the amount of data transferred over the network and stored in application memory. Furthermore, using SELECT * prevented the database from using 'covering indexes' which could significantly speed up the query.

## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
