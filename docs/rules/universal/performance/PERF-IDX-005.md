# Deep Offset Pagination (PERF-IDX-005)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Database must scan and discard all rows before the offset

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use keyset/cursor pagination instead: WHERE id > last_seen_id LIMIT n
