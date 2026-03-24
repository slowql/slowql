# Cursor Declaration (PERF-CURSOR-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Cursors process one row at a time, requiring round-trips and preventing set-based optimizations. Cursor operations are typically 10-100x slower than equivalent set-based SQL.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
