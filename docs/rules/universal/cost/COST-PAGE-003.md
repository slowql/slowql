# COUNT(*) for Pagination Total (COST-PAGE-003)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
COUNT(*) on large tables requires full table scan or index scan. For 100M row table, this can take 30+ seconds and cost significant IOPS. Users rarely navigate past page 3.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Avoid showing total counts beyond page 10. Use approximate counts or cached counts updated periodically. Show 'More results' instead of page numbers.
