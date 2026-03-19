# Inconsistent Table Naming (QUAL-NAME-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Inconsistent naming makes the schema harder to learn and navigate. It creates uncertainty for developers and often leads to bugs where the wrong table name is guessed.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Standardize on either singular (user) or plural (users) for all table names. Plural is common for collections, singular for entity definitions.
