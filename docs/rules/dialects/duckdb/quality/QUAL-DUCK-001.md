# Deprecated Old-Style Type Cast (QUAL-DUCK-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Duckdb)

## Description
Old-style casts are visually ambiguous with function calls and reduce code readability.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use CAST(value AS type) or value::type instead of type(value).
