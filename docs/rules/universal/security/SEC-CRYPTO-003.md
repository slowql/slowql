# Hardcoded Encryption Key (SEC-CRYPTO-003)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Hardcoded keys in queries appear in query logs, execution plans, source control history, and monitoring tools. Key compromise means total data compromise with no rotation path.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use HSM or dedicated key management (AWS KMS, Azure Key Vault, HashiCorp Vault). Reference keys by name/alias, never by value. Implement key rotation procedures.
