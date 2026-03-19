# SELECT INTO Temp Table Without Index (PERF-TSQL-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
Temp tables without indexes cause table scans on every join or filter.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add CREATE INDEX after SELECT INTO, or pre-create the table with indexes.
