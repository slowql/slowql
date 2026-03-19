# Old Data Not Archived (COST-ARCHIVE-001)

**Dimension**: Cost
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Storing years of logs in hot storage costs 10x vs cold storage (S3 Glacier). Old data wastes IOPS and backup capacity.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement data lifecycle: archive data > 90 days old to S3/Glacier. Use table partitioning by date.
