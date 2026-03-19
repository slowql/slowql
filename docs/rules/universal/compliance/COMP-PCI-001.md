# PAN Exposure in SQL (COMP-PCI-001)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Unmasked PANs in logs, cache, or application output violate PCI-DSS and increase the risk of financial fraud and massive non-compliance fines.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Mask PANs at the database level using Dynamic Data Masking or in the application layer. Only store the last 4 digits if full PAN is not required. Use tokenization services.
