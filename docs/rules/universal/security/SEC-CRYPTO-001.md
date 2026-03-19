# Weak Hashing Algorithm (SEC-CRYPTO-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
MD5 and SHA1 are cryptographically broken. GPU clusters can crack MD5 hashes at 200+ billion attempts/second. Rainbow tables provide instant lookups for common passwords.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use bcrypt, scrypt, or Argon2id for passwords (with appropriate cost factors). For data integrity checksums, use SHA-256 or SHA-3. Never use MD5/SHA1 for security purposes.
