# LDAP Injection in Directory Queries (SEC-INJ-007)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
LDAP injection allows attackers to bypass authentication, enumerate directory structure, and access unauthorized data. Concatenating user input into LDAP filters enables filter manipulation like SQL injection.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use parameterized LDAP queries. Escape special characters: *()\NULL. Validate input against whitelist. Use prepared LDAP statements where available. Example: escape * as \2a, ( as \28.
