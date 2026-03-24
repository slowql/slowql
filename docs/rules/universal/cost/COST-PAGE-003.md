# COUNT(*) for Pagination Total (COST-PAGE-003)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
COUNT(*) on large tables requires full table scan or index scan. For 100M row table, this can take 30+ seconds and cost significant IOPS. Users rarely navigate past page 3.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
