# Server-Side Request Forgery via Database (SEC-SSRF-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
SSRF via database allows attackers to scan internal networks, access cloud metadata services (AWS EC2 metadata at 169.254.169.254), bypass firewalls, and exfiltrate data.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Disable HTTP functions in database. If needed, use allowlist of approved URLs. Block access to private IP ranges (10.0.0.0/8, 169.254.0.0/16). Validate and sanitize all URLs.
