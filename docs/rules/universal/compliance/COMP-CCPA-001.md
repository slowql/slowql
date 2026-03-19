# Do Not Sell Flag Not Checked (COMP-CCPA-001)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Processing 'sale' of data for consumers who have opted out violates CCPA requirements, exposing the company to statutory damages and enforcement actions.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Modify all queries that share or sell data to include a check for the do_not_sell flag. Ensure it's set to FALSE before including the record.
