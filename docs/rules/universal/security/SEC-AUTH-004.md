# Password Policy Bypass (SEC-AUTH-004)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Weak passwords without policy enforcement are vulnerable to brute force and credential stuffing attacks. Non-expiring passwords increase the window for compromised credentials to be exploited.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always keep CHECK_POLICY = ON and CHECK_EXPIRATION = ON. Use strong password complexity requirements. Implement password rotation policies through database-level enforcement.
