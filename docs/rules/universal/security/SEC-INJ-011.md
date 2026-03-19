# SQL Injection via JSON Functions (SEC-INJ-011)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Concatenating user input into JSON path expressions allows attackers to modify query logic, access unauthorized data, or cause errors that reveal schema information.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use parameterized JSON paths. Validate path components against whitelist. Avoid dynamic path construction. Example: validate that path only contains allowed property names before using.
