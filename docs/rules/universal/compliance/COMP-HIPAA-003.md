# Unencrypted PHI Transit Signal (COMP-HIPAA-003)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Transmitting PHI over unencrypted connections violates the HIPAA Security Rule regarding transmission security (45 CFR § 164.312(e)(1)) and exposes data to man-in-the-middle attacks.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Enable SSL/TLS for all database connections. Update connection strings to use encrypt=true, sslmode=verify-full, or equivalent secure parameters.
