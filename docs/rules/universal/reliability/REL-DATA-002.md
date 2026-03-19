# Truncate Without Transaction (REL-DATA-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
TRUNCATE removes all rows instantly with no row-by-row logging, making recovery impossible without a backup in non-transactional databases.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Wrap TRUNCATE in an explicit BEGIN/START TRANSACTION block with a subsequent COMMIT only after verification. Prefer DELETE with WHERE for recoverable operations. Use TRUNCATE only in controlled migration scripts.
