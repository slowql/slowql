# SET QUOTED_IDENTIFIER OFF (QUAL-TSQL-002)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
With QUOTED_IDENTIFIER OFF, indexed views and computed columns cannot be created or queried. This is deprecated and will be removed in a future SQL Server version.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove SET QUOTED_IDENTIFIER OFF. Use single quotes for strings and double quotes or square brackets for identifiers.
