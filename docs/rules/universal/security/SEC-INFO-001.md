# Database Version Disclosure (SEC-INFO-001)

**Dimension**: Security
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Exposing database version helps attackers identify known vulnerabilities (CVEs) specific to that version. This information should not be accessible to application users.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Never expose version info to end users. If needed for admin purposes, require authentication and log access. Return generic error messages without version details.
