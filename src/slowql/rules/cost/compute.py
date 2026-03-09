from __future__ import annotations

"""
Cost Compute rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'ExpensiveWindowFunctionRule',
    'FullTableScanRule',
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
                partition = args.get('partition_by')
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
