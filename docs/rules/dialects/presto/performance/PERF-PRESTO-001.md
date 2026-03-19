# Implicit Cross-Join on Distributed Engine (PERF-PRESTO-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Presto)

## Description
Cross-joins on distributed engines shuffle all data. Two 1M-row tables produce 1 trillion intermediate rows across workers.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace comma-separated tables with explicit JOIN: FROM a JOIN b ON a.key = b.key.
