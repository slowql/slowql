"""
Cost Compute rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "ExpensiveWindowFunctionRule",
    "FullTableScanRule",
    "MysqlQueryCachePollutionRule",
    "MysqlQueryCachePollutionRule",
    "OracleFullTableHintRule",
    "OracleFullTableHintRule",
    "SnowflakeWarehouseSizeHintRule",
    "TsqlCursorWithoutFastForwardRule",
    "TsqlCursorWithoutFastForwardRule",
]


class FullTableScanRule(PatternRule):
    """Detects queries that likely trigger full table scans by lacking WHERE clauses."""

    id = "COST-COMPUTE-001"
    name = "Full Table Scan on Large Tables"
    description = (
        "Detects queries that likely trigger full table scans by lacking WHERE clauses "
        "on SELECT statements. Full scans consume excessive compute and I/O credits in "
        "cloud databases."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_COMPUTE

    pattern = r"\bSELECT\b(?!\s+\*\s+INTO\b).*?\bFROM\b(?:(?!\bWHERE\b).)*?(?:;|$)"
    message_template = "Potential full table scan missing WHERE clause: {match}"

    impact = (
        "Full table scans linearly increase compute cost with table size. On cloud "
        "databases (AWS RDS, Azure SQL, GCP CloudSQL), this wastes IOPS and CPU credits, "
        "especially on large tables."
    )
    fix_guidance = (
        "Add a WHERE clause to filter rows. If a full scan is truly needed, consider "
        "using a separate analytics replica or data warehouse (e.g., BigQuery, "
        "Redshift) to avoid impacting OLTP workloads and costs."
    )


class ExpensiveWindowFunctionRule(ASTRule):
    """Detects window functions used without PARTITION BY."""

    id = "COST-COMPUTE-002"
    name = "Expensive Window Functions Without Partitioning"
    description = (
        "Detects window functions (ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, etc.) used "
        "without PARTITION BY. Without partitioning, the entire dataset is processed "
        "as one partition, increasing memory and compute costs."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Window):
                args = getattr(node, "args", {})
                partition = args.get("partition_by")
                if not partition or (isinstance(partition, list) and len(partition) == 0):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="Expensive window function without PARTITION BY detected.",
                            snippet=str(node)[:100],
                            impact=(
                                "Window functions without partitioning process the entire result set in a single "
                                "partition, consuming high memory and CPU. In serverless databases (Aurora Serverless, "
                                "Synapse), this can trigger aggressive scaling and cost spikes."
                            ),
                            fix=Fix(
                                description="Add PARTITION BY clause",
                                replacement="",
                                is_safe=False,
                            ),
                        )
                    )
        return issues


class SnowflakeWarehouseSizeHintRule(PatternRule):
    """Suggests warehouse size awareness for Snowflake FLATTEN queries."""

    id = "COST-SF-003"
    name = "LATERAL FLATTEN Without Warehouse Consideration"
    description = "FLATTEN on large VARIANT arrays may need larger warehouse to avoid spilling."
    severity = Severity.INFO
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("snowflake",)
    pattern = r"\bLATERAL\s+FLATTEN\b"
    message_template = "LATERAL FLATTEN detected — verify warehouse size is appropriate: {match}"
    impact = "Undersized warehouse causes disk spilling, multiplying credit consumption."
    fix_guidance = "Monitor query profile for spilling. Scale warehouse for heavy FLATTEN operations."


class MysqlQueryCachePollutionRule(PatternRule):
    """Detects large queries without SQL_NO_CACHE in MySQL."""

    id = "COST-MYSQL-001"
    name = "Query Cache Pollution"
    description = (
        "Large analytical queries in MySQL can pollute the query cache, "
        "evicting frequently-used cached results. Use SQL_NO_CACHE for "
        "one-off or analytical queries."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("mysql",)

    pattern = r"\bSELECT\s+(?!.*\bSQL_NO_CACHE\b).*\b(?:GROUP\s+BY|ORDER\s+BY|HAVING)\b"
    message_template = "Analytical query without SQL_NO_CACHE — may pollute query cache: {match}"

    impact = (
        "Large result sets evict smaller, frequently-used entries from "
        "the query cache, degrading performance for other queries."
    )
    fix_guidance = (
        "Add SQL_NO_CACHE: SELECT SQL_NO_CACHE ... for analytical or "
        "one-off queries. Note: query cache is removed in MySQL 8.0+."
    )


class TsqlCursorWithoutFastForwardRule(PatternRule):
    """Detects DECLARE CURSOR without FAST_FORWARD in T-SQL."""

    id = "COST-TSQL-001"
    name = "Cursor Without FAST_FORWARD"
    description = (
        "T-SQL cursors default to GLOBAL KEYSET which maintains a copy "
        "of keys in tempdb. FAST_FORWARD (forward-only, read-only) is "
        "the most efficient cursor type and avoids tempdb overhead."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("tsql",)

    pattern = r"\bDECLARE\s+\w+\s+CURSOR\b(?!.*\bFAST_FORWARD\b)"
    message_template = "CURSOR without FAST_FORWARD — unnecessary tempdb overhead: {match}"

    impact = (
        "Non-FAST_FORWARD cursors maintain key sets in tempdb, consuming "
        "I/O and storage. For read-only forward iteration this is waste."
    )
    fix_guidance = (
        "Use DECLARE cur CURSOR FAST_FORWARD FOR SELECT ... "
        "Or better: replace the cursor with a set-based operation."
    )


class OracleFullTableHintRule(PatternRule):
    """Detects /*+ FULL */ hint forcing full table scan in Oracle."""

    id = "COST-ORA-001"
    name = "Full Table Scan Hint"
    description = (
        "The /*+ FULL(table) */ hint forces Oracle to perform a full table "
        "scan, bypassing all indexes. This is rarely appropriate in OLTP "
        "and wastes I/O."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("oracle",)

    pattern = r"/\*\+\s*FULL\s*\("
    message_template = "FULL table scan hint detected — bypasses all indexes: {match}"

    impact = (
        "Forces reading every block in the table regardless of available "
        "indexes. On large tables this is orders of magnitude slower."
    )
    fix_guidance = (
        "Remove the FULL hint and let the optimizer choose. If the "
        "optimizer makes poor choices, update statistics with "
        "DBMS_STATS.GATHER_TABLE_STATS."
    )
