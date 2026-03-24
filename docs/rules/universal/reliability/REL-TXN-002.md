# Autocommit Disable Detection (REL-TXN-002)

**Dimension**: Reliability
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Disabling autocommit causes uncommitted changes to be silently rolled back on connection drop or application crash, leading to data loss. Long-running implicit transactions hold locks and degrade concurrency.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
