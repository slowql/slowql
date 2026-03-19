# Unencrypted Sensitive Column Definition (COMP-SEC-001)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Storing sensitive values in plain text columns violates PCI-DSS, HIPAA, and GDPR requirements and exposes data if the database is compromised.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use application-level encryption before storing, or database-level transparent encryption. Consider column names like password_hash or token_encrypted to signal encrypted storage.
