# Repeated Subquery Instead of CTE (COST-BQ-003)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Bigquery)

## Description
Each repeated subquery scans underlying tables again, multiplying cost.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Extract into WITH (CTE) clause. BigQuery materializes CTEs referenced multiple times.
