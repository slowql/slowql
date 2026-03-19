# Cursor Without FAST_FORWARD (COST-TSQL-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
Non-FAST_FORWARD cursors maintain key sets in tempdb, consuming I/O and storage. For read-only forward iteration this is waste.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use DECLARE cur CURSOR FAST_FORWARD FOR SELECT ... Or better: replace the cursor with a set-based operation.
