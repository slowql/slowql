# Table Lock Hint (PERF-LOCK-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Table-level locks (TABLOCK, TABLOCKX) block ALL concurrent access to the table. Under load, this creates cascading waits that can freeze the entire application.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
