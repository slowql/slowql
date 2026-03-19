# Cold Start Query Pattern (COST-SERVERLESS-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Complex queries trigger Aurora Capacity Unit (ACU) scaling. Each scale-up costs minimum $0.12/hour. Frequent scaling wastes budget.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Keep queries simple in serverless. Pre-aggregate data or use materialized views. Set minimum ACUs appropriately.
