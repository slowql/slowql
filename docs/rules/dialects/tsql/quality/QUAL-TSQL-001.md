# SET ANSI_NULLS OFF (QUAL-TSQL-001)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
Code relying on ANSI_NULLS OFF will break when the setting is removed.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use IS NULL instead of = NULL. Remove SET ANSI_NULLS OFF.
