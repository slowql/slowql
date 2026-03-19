# CVV Storage Violation (COMP-PCI-002)

**Dimension**: Compliance
**Severity**: Critical
**Scope**: Universal (All Dialects)

## Description
Storing CVV/CVC is a major PCI-DSS violation. It makes the database a prime target for attackers, as stolen CVVs enable 'CNP' (Card Not Present) fraud.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
DELETE all columns and code that store CVV/CVC. These values must only be used during the real-time authorization process and never persisted to disk.
