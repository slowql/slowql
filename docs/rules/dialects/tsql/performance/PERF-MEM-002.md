# Unbounded Temp Table Creation (PERF-MEM-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
Unbounded SELECT INTO can fill tempdb, crash the instance, or exhaust memory. A single runaway query can impact all database users.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always add WHERE clause or TOP/LIMIT to bound result size. Pre-create temp table with explicit schema for better memory estimation.
