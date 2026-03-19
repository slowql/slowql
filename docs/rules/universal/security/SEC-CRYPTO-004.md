# Weak Encryption Algorithm (SEC-CRYPTO-004)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
DES uses 56-bit keys, crackable in hours. RC4 has critical biases. These algorithms are prohibited by PCI-DSS, HIPAA, and most compliance frameworks.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use AES-256-GCM for symmetric encryption. Migrate existing encrypted data to modern algorithms. Document encryption standards in security policy.
