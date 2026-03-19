# ROWNUM Without ORDER BY (QUAL-ORA-001)

**Dimension**: Quality
**Severity**: High
**Scope**: Dialect Specific (Oracle)

## Description
ROWNUM filters rows BEFORE ORDER BY is applied. SELECT * FROM t WHERE ROWNUM <= 10 ORDER BY date returns 10 arbitrary rows then sorts them — not the top 10 by date. Results are non-deterministic and change with optimizer plan.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Wrap in a subquery: SELECT * FROM (SELECT * FROM t ORDER BY date) WHERE ROWNUM <= 10. Or use the modern FETCH FIRST syntax: SELECT * FROM t ORDER BY date FETCH FIRST 10 ROWS ONLY.
