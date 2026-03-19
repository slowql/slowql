# Privilege Escalation via Role Grant (SEC-AUTHZ-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Unrestricted admin access enables total database compromise. Attackers target privilege escalation as first step after initial access. Violates SOX segregation of duties.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement approval workflow for privilege grants. Use time-limited elevated access. Log all privilege changes. Review roles quarterly.
