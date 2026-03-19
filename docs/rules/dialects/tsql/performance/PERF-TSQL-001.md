# Missing SET NOCOUNT ON (PERF-TSQL-001)

**Dimension**: Performance
**Severity**: Info
**Scope**: Dialect Specific (Tsql)

## Description
Each INSERT, UPDATE, DELETE inside the procedure sends a 'N rows affected' message to the client. This adds network overhead and can cause ADO.NET and other drivers to misinterpret result sets.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add SET NOCOUNT ON as the first statement in every stored procedure and trigger. This is a universal T-SQL best practice.
