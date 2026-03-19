# Scalar UDF in SELECT/WHERE (PERF-SCALAR-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
Scalar UDFs execute row-by-row, prevent parallelism, and cannot be inlined in most SQL versions. A single scalar UDF can make queries 100x slower.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Rewrite as inline table-valued function (iTVF) or move logic to application layer.
