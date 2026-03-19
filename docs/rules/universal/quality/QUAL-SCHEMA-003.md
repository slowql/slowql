# Missing Index on Foreign Key (QUAL-SCHEMA-003)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
JOINs and CASCADE deletes on unindexed foreign keys are extremely slow. They cause full table scans for every referenced record lookup, killing performance.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Create an INDEX on the foreign key column. Most databases do not index FKs automatically. Example: CREATE INDEX idx_users_id ON profiles(user_id).
