# Server-Side Template Injection (SEC-INJ-010)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Template injection allows arbitrary code execution on the server. If user input is embedded in template syntax ({{}}, {%%}), attackers can execute system commands.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Never use user input in template strings. Use static templates only. If dynamic content is needed, use safe interpolation methods. Escape template syntax characters. Sandbox template execution.
