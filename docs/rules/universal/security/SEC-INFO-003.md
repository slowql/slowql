# Timing Attack Pattern (SEC-INFO-003)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
String comparison of passwords has variable timing based on match length. Attackers can infer password characters through timing analysis. Each character leak reduces brute-force complexity.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use constant-time comparison for password verification. Hash passwords and compare hashes. Add artificial delays to equalize timing. Use bcrypt/Argon2 which have built-in constant-time comparison.
