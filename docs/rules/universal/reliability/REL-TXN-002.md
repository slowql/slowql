# Autocommit Disable Detection (REL-TXN-002)

**Dimension**: Reliability
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Disabling autocommit causes uncommitted changes to be silently rolled back on connection drop or application crash, leading to data loss. Long-running implicit transactions hold locks and degrade concurrency.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use explicit BEGIN/COMMIT blocks instead of disabling autocommit globally. If autocommit must be disabled, ensure every code path has explicit COMMIT or ROLLBACK. Monitor for long-running transactions via pg_stat_activity or information_schema.innodb_trx.
