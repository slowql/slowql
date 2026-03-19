# Subquery Missing Alias (QUAL-STYLE-003)

**Dimension**: Quality
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Unaliased subqueries cause syntax errors in PostgreSQL and MySQL. Even where accepted, they make the query unreadable and unreferenceable in outer query clauses.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add an alias after the closing parenthesis: FROM (SELECT ...) AS subquery_name. Choose a descriptive alias that reflects the subquery's purpose.
