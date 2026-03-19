# Permanent Temporary Table (QUAL-DEBT-002)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Temporary tables that aren't dropped consume memory and disk space in the temporary tablespace. Over time, they can cause disk full errors and slow down the database.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always DROP temporary tables as soon as they are no longer needed. Use 'ON COMMIT DROP' if supported by your database.
