# Deep Pagination Without Cursor (COST-PAGE-002)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Deep pagination (OFFSET > 1000) means scanning thousands of rows per page. Cloud databases charge per row scanned. Users on page 100+ generate 100x more cost than page 1 users.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement cursor-based pagination: return cursor token with last record ID. Next page: WHERE id > cursor ORDER BY id LIMIT 100.
