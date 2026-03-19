# Wildcard in EXISTS Subquery (QUAL-STYLE-002)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
SELECT * in EXISTS subqueries may prevent optimizer shortcuts in some databases and increases the surface area for column-level permission errors.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace 'EXISTS (SELECT * FROM ...)' with 'EXISTS (SELECT 1 FROM ...)'. SELECT 1 clearly signals intent and is universally optimized.
