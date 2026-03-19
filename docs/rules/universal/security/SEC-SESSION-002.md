# Session Timeout Not Enforced (SEC-SESSION-002)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Sessions without expiration validation remain valid indefinitely. Stolen tokens provide permanent access. Violates security best practices and compliance requirements.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always validate token expiration: WHERE token = ? AND expires_at > NOW(). Implement absolute timeouts (24h) and idle timeouts (30min). Force re-authentication for sensitive operations.
