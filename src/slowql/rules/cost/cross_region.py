"""
Cost Cross region rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "CrossDatabaseJoinRule",
    "DistributedTransactionOverheadRule",
    "MultiRegionQueryLatencyRule",
]


class CrossDatabaseJoinRule(ASTRule):
    """Detects JOIN across different databases."""

    id = "COST-CROSS-001"
    name = "Cross-Database JOIN"
    description = (
        "Detects JOIN across different databases, which forces data transfer and "
        "prevents query optimization."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_CROSS_DATABASE

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                databases = set()
                for table in node.find_all(exp.Table):
                    db_name = None
                    if hasattr(table, "db") and table.db:
                        db_name = str(table.db)
                    elif "." in str(table):
                        parts = str(table).split(".")
                        if len(parts) >= 3:
                            db_name = parts[0]

                    if db_name:
                        databases.add(db_name)

                if len(databases) > 1:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"Cross-database JOIN detected ({databases}) - forces data transfer and prevents optimization",
                            snippet=str(node)[:100],
                        )
                    )
        return issues

    impact = (
        "Cross-database JOINs cannot use indexes across boundaries. Forces full table "
        "scans and data copying. In cloud, this means egress charges and 10-100x "
        "slower queries."
    )
    fix_guidance = (
        "Denormalize data into single database or use ETL to replicate needed data. "
        "Consider microservices with API calls instead of cross-DB queries."
    )


class MultiRegionQueryLatencyRule(PatternRule):
    """Detects queries indicating cross-region data access."""

    id = "COST-CROSS-002"
    name = "Multi-Region Query Latency"
    description = (
        "Detects queries using database links, federated tables, or region qualifiers "
        "indicating cross-region data access."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_CROSS_REGION

    pattern = r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^;]*\b(us-east|us-west|eu-west|ap-south|@[^.]*\..*\.rds\.amazonaws\.com|@[^.]*\.database\.windows\.net)\b"
    message_template = "Multi-region query detected: potential latency and egress costs: {match}"

    impact = (
        "Cross-region queries add 50-200ms latency per request. Egress charges "
        "of $0.02-0.12/GB also apply."
    )
    fix_guidance = (
        "Use read replicas in each region or implement a caching layer (Redis) "
        "for cross-region reads."
    )


class DistributedTransactionOverheadRule(PatternRule):
    """Detects distributed transaction patterns."""

    id = "COST-CROSS-003"
    name = "Distributed Transaction Overhead"
    description = (
        "Detects distributed transaction patterns (BEGIN DISTRIBUTED TRANSACTION, XA START) "
        "that are 10-100x slower than local transactions."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_DISTRIBUTED

    pattern = r"\b(BEGIN\s+DISTRIBUTED\s+TRANSACTION|XA\s+START|START\s+TRANSACTION\s+WITH\s+CONSISTENT\s+SNAPSHOT)\b"
    message_template = (
        "Distributed transaction detected: major performance and cost overhead: {match}"
    )

    impact = (
        "Distributed transactions require 2-phase commit across nodes, holding locks "
        "for network round-trips. Throughput drops significantly."
    )
    fix_guidance = (
        "Avoid distributed transactions. Use Saga pattern for cross-service consistency. "
        "Implement compensating transactions or eventual consistency."
    )
