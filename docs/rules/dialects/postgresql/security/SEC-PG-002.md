# Search Path Manipulation (SEC-PG-002)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Postgresql)

## Description
An attacker who can SET search_path can place a trojan function or table in a schema that appears earlier in the path, hijacking queries that use unqualified names.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
