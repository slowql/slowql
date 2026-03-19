# OFFSET Pagination Without Index (COST-PAGE-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
OFFSET 10000 forces the database to scan and discard 10,000 rows. On page 1000, you pay for scanning 1 million rows. In cloud databases, this means IOPS charges for wasted work.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use keyset/cursor pagination: WHERE id > last_seen_id ORDER BY id LIMIT 100. This maintains constant cost per page. For random access, use search indexing.
