# Duplicate Index Signal (COST-IDX-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Duplicate indexes waste storage (each index = 100% of indexed data), slow down writes (every INSERT/UPDATE maintains all indexes), and cost money in cloud storage charges.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Query system catalog to find duplicates (e.g., pg_indexes). Keep only the most selective index. Use covering indexes instead of multiple single-column indexes.
