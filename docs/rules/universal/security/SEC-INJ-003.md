# Tautological OR Condition (SEC-INJ-003)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Tautological OR conditions bypass authentication and authorization checks, allowing attackers to retrieve all rows, bypass login forms, or escalate privileges.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use parameterized queries to prevent injection. If the tautological condition is intentional (e.g., for testing), remove it before deploying to production. Investigate the source of the query for injection vulnerabilities.
