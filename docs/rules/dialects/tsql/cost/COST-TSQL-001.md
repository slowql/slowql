# Cursor Without FAST_FORWARD (COST-TSQL-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
Non-FAST_FORWARD cursors maintain key sets in tempdb, consuming I/O and storage. For read-only forward iteration this is waste.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
