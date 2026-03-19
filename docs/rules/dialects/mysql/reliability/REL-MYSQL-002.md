# REPLACE INTO Deletes and Reinserts (REL-MYSQL-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Mysql)

## Description
REPLACE INTO deletes the existing row and inserts a new one when a duplicate key is found. This resets AUTO_INCREMENT IDs, fires DELETE triggers unexpectedly, and breaks foreign key references silently.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use INSERT ... ON DUPLICATE KEY UPDATE instead. It updates only specified columns without deleting the row, preserving IDs, timestamps, and foreign key integrity.
