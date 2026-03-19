# Missing Batch Size in Loop (PERF-BATCH-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
WHILE loops without batch limits may process unlimited rows per iteration, negating the benefits of batching.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always use TOP/LIMIT in batched operations inside loops.
