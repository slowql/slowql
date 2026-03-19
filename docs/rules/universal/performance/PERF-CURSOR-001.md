# Cursor Declaration (PERF-CURSOR-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Cursors process one row at a time, requiring round-trips and preventing set-based optimizations. Cursor operations are typically 10-100x slower than equivalent set-based SQL.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Rewrite using set-based operations: UPDATE...FROM, MERGE, window functions. If cursor is truly necessary, use FAST_FORWARD READ_ONLY.
