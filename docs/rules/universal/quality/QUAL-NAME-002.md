# Ambiguous Alias (QUAL-NAME-002)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Single-letter aliases make complex queries impossible to read without constant referencing back to the source. They hide the semantic meaning of the data.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use 3+ character descriptive aliases. Example: 'cust' for customers, 'emp' for employees. Avoid aliases like 'a', 'b', 't1'.
