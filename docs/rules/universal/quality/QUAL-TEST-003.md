# Hardcoded Test Data (QUAL-TEST-003)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Leftover test data markers in production queries indicate poor release hygiene. They can accidentally filter out real data or expose test logic to users.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove test data filters from production queries. Use proper environment configuration to separate test and production logic.
