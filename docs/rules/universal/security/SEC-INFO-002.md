# Schema Information Disclosure (SEC-INFO-002)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Schema enumeration reveals table names, column names, and relationships. Attackers use this for targeted SQL injection and privilege escalation. Should be restricted to DBAs only.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Restrict access to system catalogs using database permissions. Don't expose schema info through application errors. Use views to hide underlying schema from application.
