# Cross-Database JOIN (COST-CROSS-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Cross-database JOINs cannot use indexes across boundaries. Forces full table scans and data copying. In cloud, this means egress charges and 10-100x slower queries.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
