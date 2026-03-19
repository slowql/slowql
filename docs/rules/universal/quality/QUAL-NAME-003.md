# Hungarian Notation in Names (QUAL-NAME-003)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Hungarian notation is redundant in SQL as types are defined in schema. It makes renaming/typing changes harder and clutters the code with obsolete metaphors.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove type prefixes. Use 'name' instead of 'str_name', 'id' instead of 'int_id'. Database metadata already provides type information.
