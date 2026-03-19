# Leading Wildcard Search (PERF-IDX-002)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Forces a full table scan because B-Tree indexes cannot be traversed in reverse.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use Full-Text Search (e.g., Elasticsearch, Postgres FTS) for substring searches.
