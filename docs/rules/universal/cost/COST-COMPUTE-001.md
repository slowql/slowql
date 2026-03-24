# Full Table Scan on Large Tables (COST-COMPUTE-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Full table scans linearly increase compute cost with table size. On cloud databases (AWS RDS, Azure SQL, GCP CloudSQL), this wastes IOPS and CPU credits, especially on large tables.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
