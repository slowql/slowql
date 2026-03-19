# Function on Indexed Column (PERF-IDX-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Prevents index usage, forces full table scan

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use functional indexes or rewrite predicate without wrapping function
