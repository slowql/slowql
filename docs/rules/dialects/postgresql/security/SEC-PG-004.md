# SECURITY DEFINER Without search_path (SEC-PG-004)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Postgresql)

## Description
An attacker sets search_path to a schema with trojan objects, then calls the SECURITY DEFINER function. The function resolves unqualified names to the attacker's schema with owner privileges.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
