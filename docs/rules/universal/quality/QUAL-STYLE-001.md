# SELECT Without FROM Clause (QUAL-STYLE-001)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Constant SELECT statements in application queries may indicate debug code left in production, test artifacts, or incomplete query construction.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove debug SELECT statements before deployment. If the constant expression is needed, use database-specific syntax like SELECT 1 FROM DUAL (Oracle) or ensure the intent is documented.
