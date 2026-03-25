# Missing SET NOCOUNT ON (PERF-TSQL-001)

**Dimension**: Performance
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Each INSERT, UPDATE, DELETE inside the procedure sends a 'N rows affected' message to the client. This adds network overhead and can cause ADO.NET and other drivers to misinterpret result sets.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
