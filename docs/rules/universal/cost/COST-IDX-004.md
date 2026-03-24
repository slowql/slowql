# Redundant Index Column Order (COST-IDX-004)

**Dimension**: Cost
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Index (col_B, col_A) cannot optimize WHERE col_A = ?. Column order matters. Wrong order = wasted index and slower queries.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
