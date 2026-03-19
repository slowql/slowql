# Large Text Column Without Compression (COST-COMPRESS-001)

**Dimension**: Cost
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Uncompressed TEXT columns waste 3-10x storage space. Cloud storage charges are significant for uncompressed data.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Enable row/page compression (e.g., ROW_FORMAT=COMPRESSED in MySQL). Use JSONB instead of TEXT for JSON data.
