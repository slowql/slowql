# Right to Erasure — Verify Cascade Completeness (COMP-GDPR-003)

**Dimension**: Compliance
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Incomplete erasure leaves PII in related tables, audit logs, caches, and backups, violating GDPR Article 17 and exposing the organization to regulatory penalties.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement cascading deletes or a dedicated erasure procedure that covers all related tables. Document which systems hold personal data and verify backup purge schedules. Consider pseudonymization as an alternative to deletion.
