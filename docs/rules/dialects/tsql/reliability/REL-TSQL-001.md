# @@IDENTITY Instead of SCOPE_IDENTITY() (REL-TSQL-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
If a trigger on the target table inserts into another table with an identity column, @@IDENTITY returns the trigger's identity value instead of the intended one, causing silent data corruption.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use SCOPE_IDENTITY() to get the last identity value generated in the current scope. For parallel inserts use OUTPUT clause.
