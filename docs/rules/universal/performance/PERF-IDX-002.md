# Leading Wildcard Search (PERF-IDX-002)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description


**Rationale:**
B-Tree indexes are sorted from left to right. When a query uses a leading wildcard (e.g., '%abc'), the database cannot use the index to find the starting point. This forces a full table scan, which is extremely slow on large tables.

## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
