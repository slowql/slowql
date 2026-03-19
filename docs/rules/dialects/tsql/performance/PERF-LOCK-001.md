# Table Lock Hint (PERF-LOCK-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
Table-level locks (TABLOCK, TABLOCKX) block ALL concurrent access to the table. Under load, this creates cascading waits that can freeze the entire application.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove table lock hints unless absolutely necessary. Use row-level locking (default behavior).
