# Wildcard in EXISTS Subquery (QUAL-STYLE-002)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
SELECT * in EXISTS subqueries may prevent optimizer shortcuts in some databases and increases the surface area for column-level permission errors.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
