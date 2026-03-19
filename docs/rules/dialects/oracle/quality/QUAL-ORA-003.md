# NVL in WHERE Clause (QUAL-ORA-003)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Oracle)

## Description
NVL() makes the predicate non-SARGable.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace NVL(col, val) = x with (col = x OR col IS NULL).
