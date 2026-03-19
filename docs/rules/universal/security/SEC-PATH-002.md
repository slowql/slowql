# Local File Inclusion (SEC-PATH-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Including SQL files based on user input allows attackers to execute arbitrary SQL code. If attacker can upload a .sql file, they can execute it via file inclusion.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Never include SQL files based on user input. Use whitelist of allowed procedures. Validate against allowed set of script names. Store procedures in database, not files.
