# Rules Overview

SlowQL ships with **272 analysis rules** designed to catch mistakes before they impact production. Rules are categorized across **6 dimensions** and graded on **4 severity levels**.

## Dimensions

Every rule belongs to a dimension that describes the class of issue it detects:

1. **Security (`SEC-`)**  
   Targets vulnerabilities like SQL injection, hardcoded credentials, bypass checks, and improper path variables.

2. **Performance (`PERF-`)**  
   Highlights unindexed lookups, `SELECT *` anti-patterns, non-SARGable operators, and inefficient joins that impact database latency.

3. **Cost (`COST-`)**  
   Designed to save money in cloud environments (like Snowflake and BigQuery). Warns against full table scans, Cartesian products, and improper clustering strategies that cause massive billing spikes.

4. **Reliability (`REL-`)**  
   Focuses on preventing logic bugs: missing `WHERE` clauses on `DELETE`/`UPDATE` statements, transaction state bugs, lock collisions, and idempotency guarantees.

5. **Compliance (`COMP-`)**  
   Data governance checks. Warns you when processing sensitive column names corresponding to `GDPR`, `HIPAA`, `PCI-DSS` without appropriate masking/hashing functions.

6. **Quality (`QUAL-`)**  
   Enforces style guides, naming conventions, and modern SQL adoption (e.g., favoring `JOIN` over implicit comma joins).

## Severity Levels

SlowQL assigns one of four severity levels to every issue. By default, pipelines and CLI runs fail on `high` severity.

- **Critical:** Will undoubtedly cause production outages, massive security breaches, or data loss. (Example: `DELETE` without a `WHERE` condition or severe SQL injection).
- **High:** Serious design flaws that cause severe performance degradation or expose data improperly. (Example: Cross-joining massive tables without indexes).
- **Medium:** Suboptimal queries or minor technical debts that require fixing before deploying to production. (Example: `SELECT *` over a 50-column table).
- **Low:** Style, naming or micro-optimizations. (Example: Trailing commas, capitalization inconsistencies).

## Safe Autofix

Many rules are designated with `FixConfidence.SAFE` and `RemediationMode.SAFE_APPLY`. These rules offer a string or AST transformation that guarantees 100% semantic equivalency. By using `slowql --fix`, SlowQL will instantly rewrite your SQL without altering its logic.

## Viewing the Rules

The fastest way to view details about specific rules is directly via the CLI:

```bash
# List all 272 rules
slowql --list-rules

# Filter rules to only show Performance checks for Postgres
slowql --list-rules --filter-dimension performance --filter-dialect postgresql

# Read the full documentation of a specific rule
slowql --explain PERF-SCAN-001
```
