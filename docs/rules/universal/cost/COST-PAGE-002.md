# Deep Pagination Without Cursor (COST-PAGE-002)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Deep pagination (OFFSET > 1000) means scanning thousands of rows per page. Cloud databases charge per row scanned. Users on page 100+ generate 100x more cost than page 1 users.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
