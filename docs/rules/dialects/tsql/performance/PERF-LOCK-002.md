# NOLOCK / Read Uncommitted Hint (PERF-LOCK-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
NOLOCK reads uncommitted data (dirty reads), can skip rows, read rows twice, or return phantom data. It's not 'faster' — it's 'wrong'.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use READ COMMITTED SNAPSHOT ISOLATION (RCSI) for non-blocking reads without dirty reads.
