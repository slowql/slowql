# Hardcoded Password (SEC-AUTH-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Credentials exposed in source code or logs can be used by attackers.

**Rationale:**
Secrets should never be stored in plain text within code or queries.

## Remediation / Fix
Use query parameters and secrets management.
