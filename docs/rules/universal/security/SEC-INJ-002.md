# Dynamic SQL Execution (SEC-INJ-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Attackers can inject arbitrary SQL through unsanitized inputs passed into dynamically constructed queries, leading to data theft, privilege escalation, or complete database compromise.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use parameterized queries or stored procedures with typed parameters. Replace string concatenation with sp_executesql parameter binding. For MySQL, use PREPARE with placeholder syntax (?) instead of variable interpolation.
