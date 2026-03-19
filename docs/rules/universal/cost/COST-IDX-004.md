# Redundant Index Column Order (COST-IDX-004)

**Dimension**: Cost
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Index (col_B, col_A) cannot optimize WHERE col_A = ?. Column order matters. Wrong order = wasted index and slower queries.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Order index columns by selectivity and query usage. For queries filtering col_A then col_B, use INDEX(col_A, col_B).
