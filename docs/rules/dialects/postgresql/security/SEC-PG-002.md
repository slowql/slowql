# Search Path Manipulation (SEC-PG-002)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Postgresql)

## Description
An attacker who can SET search_path can place a trojan function or table in a schema that appears earlier in the path, hijacking queries that use unqualified names.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always use schema-qualified names (schema.table, schema.function). Restrict SET search_path permissions using REVOKE. Use ALTER ROLE ... SET search_path for controlled defaults.
