# Cross-Database JOIN (COST-CROSS-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Cross-database JOINs cannot use indexes across boundaries. Forces full table scans and data copying. In cloud, this means egress charges and 10-100x slower queries.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Denormalize data into single database or use ETL to replicate needed data. Consider microservices with API calls instead of cross-DB queries.
