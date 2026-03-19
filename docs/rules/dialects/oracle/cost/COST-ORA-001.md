# Full Table Scan Hint (COST-ORA-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Oracle)

## Description
Forces reading every block in the table regardless of available indexes. On large tables this is orders of magnitude slower.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove the FULL hint and let the optimizer choose. If the optimizer makes poor choices, update statistics with DBMS_STATS.GATHER_TABLE_STATS.
