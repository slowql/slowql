# Full Table Scan on Large Tables (COST-COMPUTE-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Full table scans linearly increase compute cost with table size. On cloud databases (AWS RDS, Azure SQL, GCP CloudSQL), this wastes IOPS and CPU credits, especially on large tables.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add a WHERE clause to filter rows. If a full scan is truly needed, consider using a separate analytics replica or data warehouse (e.g., BigQuery, Redshift) to avoid impacting OLTP workloads and costs.
