# Schema Ownership Change (SEC-AUTHZ-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Schema owners have implicit full control over all objects. Ownership transfer can bypass explicit DENY permissions and grant unexpected access.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Restrict ownership changes to DBA team only. Audit all authorization changes. Use explicit permissions instead of relying on ownership.
