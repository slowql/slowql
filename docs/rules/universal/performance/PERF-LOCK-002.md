# NOLOCK / Read Uncommitted Hint (PERF-LOCK-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
NOLOCK reads uncommitted data (dirty reads), can skip rows, read rows twice, or return phantom data. It's not 'faster' — it's 'wrong'.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
