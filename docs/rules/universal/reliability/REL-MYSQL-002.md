# REPLACE INTO Deletes and Reinserts (REL-MYSQL-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
REPLACE INTO deletes the existing row and inserts a new one when a duplicate key is found. This resets AUTO_INCREMENT IDs, fires DELETE triggers unexpectedly, and breaks foreign key references silently.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
