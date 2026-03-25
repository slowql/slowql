# SELECT * in BigQuery Scans All Columns (COST-BQ-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
BigQuery charges per byte scanned. SELECT * on a 1TB table with 50 columns costs 50x more than selecting only the 1 column you need. At $5/TB, a daily job doing SELECT * can cost thousands per month unnecessarily.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
