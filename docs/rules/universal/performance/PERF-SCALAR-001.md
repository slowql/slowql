# Scalar UDF in SELECT/WHERE (PERF-SCALAR-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Scalar UDFs execute row-by-row, prevent parallelism, and cannot be inlined in most SQL versions. A single scalar UDF can make queries 100x slower.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
