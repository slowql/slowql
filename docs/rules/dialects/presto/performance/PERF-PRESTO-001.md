# Implicit Cross-Join on Distributed Engine (PERF-PRESTO-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Presto)

## Description
Cross-joins on distributed engines shuffle all data. Two 1M-row tables produce 1 trillion intermediate rows across workers.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
