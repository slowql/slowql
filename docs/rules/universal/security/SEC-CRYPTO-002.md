# Plaintext Password in Query (SEC-CRYPTO-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Plaintext passwords in databases are catastrophic during breaches. A single leaked backup exposes all credentials. Violates every security compliance framework.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Hash passwords at the application layer using bcrypt/Argon2id BEFORE SQL insertion. Never pass plaintext passwords through SQL. Store only the hash.
