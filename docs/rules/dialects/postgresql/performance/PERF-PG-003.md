# NOT IN With Potentially NULLable Subquery (PERF-PG-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Postgresql)

## Description
A single NULL in the subquery result causes NOT IN to return zero rows.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace NOT IN (SELECT ...) with NOT EXISTS (SELECT 1 FROM ... WHERE ...).
