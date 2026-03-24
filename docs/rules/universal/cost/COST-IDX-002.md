# Over-Indexed Table Signal (COST-IDX-002)

**Dimension**: Cost
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Tables with 10+ indexes pay massive write penalties. Each INSERT updates all indexes. Write throughput can drop 90%. Cloud databases charge for IOPS consumed by index maintenance.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
