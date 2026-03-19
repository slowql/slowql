# SECURITY DEFINER Without search_path (SEC-PG-004)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Postgresql)

## Description
An attacker sets search_path to a schema with trojan objects, then calls the SECURITY DEFINER function. The function resolves unqualified names to the attacker's schema with owner privileges.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add SET search_path = pg_catalog to the function: CREATE FUNCTION ... SECURITY DEFINER SET search_path = pg_catalog.
