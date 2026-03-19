# SELECT * in BigQuery Scans All Columns (COST-BQ-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Dialect Specific (Bigquery)

## Description
BigQuery charges per byte scanned. SELECT * on a 1TB table with 50 columns costs 50x more than selecting only the 1 column you need. At $5/TB, a daily job doing SELECT * can cost thousands per month unnecessarily.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always specify only the columns you need. Use column pruning: SELECT id, name, date FROM table. Partition and cluster tables on frequently filtered columns to reduce scan cost.
