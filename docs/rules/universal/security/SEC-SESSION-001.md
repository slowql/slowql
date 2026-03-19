# Insecure Session Token Storage (SEC-SESSION-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Unhashed session tokens in databases can be stolen and replayed. Database dumps, SQL injection, or backup exposure immediately compromises all active sessions.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Store only hashed tokens (SHA-256 is sufficient for tokens with high entropy). Compare using hash, not plaintext. Implement short token TTLs and secure rotation.
