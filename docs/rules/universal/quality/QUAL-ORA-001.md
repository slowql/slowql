# ROWNUM Without ORDER BY (QUAL-ORA-001)

**Dimension**: Quality
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
ROWNUM filters rows BEFORE ORDER BY is applied. SELECT * FROM t WHERE ROWNUM <= 10 ORDER BY date returns 10 arbitrary rows then sorts them — not the top 10 by date. Results are non-deterministic and change with optimizer plan.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
