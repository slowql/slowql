# Marketing Insert Without Consent Signal (COMP-GDPR-004)

**Dimension**: Compliance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Adding users to marketing lists without recorded consent violates GDPR Article 7 and ePrivacy Directive, exposing the organization to regulatory complaints and fines.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Ensure consent is recorded in a consent management table before INSERT. Include consent_id or consent_timestamp as a required foreign key in marketing tables. Audit consent validity before each campaign.
