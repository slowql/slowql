# NoSQL Injection Pattern (SEC-INJ-008)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
NoSQL injection in JSON queries allows filter bypass, data extraction, and denial of service. MongoDB-style operators like $where, $ne can be injected to bypass authentication.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Parameterize JSON queries. Use ORM/ODM libraries with prepared statements. Validate JSON structure. Never concatenate user input into JSON filter strings. Example: use parameterized MongoDB queries, not string concatenation.
