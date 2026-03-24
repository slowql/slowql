# OFFSET Pagination Without Index (COST-PAGE-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
OFFSET 10000 forces the database to scan and discard 10,000 rows. On page 1000, you pay for scanning 1 million rows. In cloud databases, this means IOPS charges for wasted work.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
