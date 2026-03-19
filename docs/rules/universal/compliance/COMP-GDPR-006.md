# Consent Withdrawal Not Honored (COMP-GDPR-006)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Failing to honor consent withdrawal violates GDPR Article 7. Continuing to process data after consent is revoked is a major non-compliance event.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always include a consent check in the WHERE clause when querying personal data for processing categories that require consent.
