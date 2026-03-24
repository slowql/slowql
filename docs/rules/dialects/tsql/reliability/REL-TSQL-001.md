# @@IDENTITY Instead of SCOPE_IDENTITY() (REL-TSQL-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
If a trigger on the target table inserts into another table with an identity column, @@IDENTITY returns the trigger's identity value instead of the intended one, causing silent data corruption.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
