# Grant to PUBLIC Role (SEC-AUTH-002)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Granting permissions to PUBLIC gives every current and future database user access to the specified objects, creating an uncontrollable access surface and potential data exposure.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Grant permissions to specific roles or users instead of PUBLIC. Create application-specific roles with minimal required permissions and assign users to those roles.
