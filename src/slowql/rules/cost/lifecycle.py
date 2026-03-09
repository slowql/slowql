"""
Cost Lifecycle rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'LargeTableWithoutPartitioningRule',
    'LargeTextColumnWithoutCompressionRule',
    'OldDataNotArchivedRule',
]


class OldDataNotArchivedRule(ASTRule):
    """Detects queries suggesting potential for data archival."""

    id = "COST-ARCHIVE-001"
    name = "Old Data Not Archived"
    description = (
        "Detects SELECT on tables with date columns, suggesting potential for "
        "archival of old data to reduce hot storage costs."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_ARCHIVAL

    _date_columns = {
        "created_at", "updated_at", "modified_at", "date", "timestamp",
        "event_date", "order_date", "transaction_date", "posted_at"
    }

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                has_date_col = False
                for col in node.find_all(exp.Column):
                    if col.name.lower() in self._date_columns:
                        has_date_col = True
                        break

                if has_date_col:
                    where = node.args.get("where")
                    filters_by_date_range = False
                    hits_old_data = False

                    if where:
                        # Check if any date column is used in the filter
                        for col in where.find_all(exp.Column):
                            if col.name.lower() in self._date_columns:
                                filters_by_date_range = True

                        # Check specifically for "older than" filters (<, <=)
                        for bin_op in where.find_all((exp.LT, exp.LTE)):
                            for col in bin_op.find_all(exp.Column):
                                if col.name.lower() in self._date_columns:
                                    hits_old_data = True

                    # Trigger if no date filter is present, or if it's specifically hitting old data
                    if not filters_by_date_range or hits_old_data:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message="Query on table with timestamp - consider archiving old data to reduce storage costs",
                                snippet=str(node)[:100],
                            )
                        )
        return issues

    impact = (
        "Storing years of logs in hot storage costs 10x vs cold storage (S3 Glacier). "
        "Old data wastes IOPS and backup capacity."
    )
    fix_guidance = (
        "Implement data lifecycle: archive data > 90 days old to S3/Glacier. Use "
        "table partitioning by date."
    )


class LargeTextColumnWithoutCompressionRule(PatternRule):
    """Detects large TEXT columns that should use compression."""

    id = "COST-COMPRESS-001"
    name = "Large Text Column Without Compression"
    description = (
        "Detects CREATE TABLE with large VARCHAR/TEXT columns that should use compression "
        "to save storage costs."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_STORAGE

    pattern = r"\bCREATE\s+TABLE\b[^;]*\b(VARCHAR\s*\(\s*\d{4,}\)|TEXT|CLOB|NVARCHAR\s*\(MAX\)|LONGTEXT)\b"
    message_template = "Large text column without compression detected: {match}"

    impact = (
        "Uncompressed TEXT columns waste 3-10x storage space. Cloud storage charges "
        "are significant for uncompressed data."
    )
    fix_guidance = (
        "Enable row/page compression (e.g., ROW_FORMAT=COMPRESSED in MySQL). Use "
        "JSONB instead of TEXT for JSON data."
    )


class LargeTableWithoutPartitioningRule(ASTRule):
    """Detects queries on likely large tables without partition pruning."""

    id = "COST-PARTITION-001"
    name = "Large Table Without Partitioning"
    description = (
        "Detects queries on large tables without partition pruning signals, "
        "which can be extremely expensive on large datasets."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_PARTITIONING

    _large_table_patterns = {
        "events", "logs", "transactions", "clickstream", "analytics",
        "audit", "history", "archive", "sessions", "metrics"
    }

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                tables = self._get_tables(ast)
                for table in tables:
                    table_lower = table.lower()
                    is_large = any(p in table_lower for p in self._large_table_patterns)

                    if is_large:
                        has_partition = "PARTITION" in query.raw.upper()
                        if not has_partition:
                            issues.append(
                                self.create_issue(
                                    query=query,
                                    message=f"Query on large table '{table}' without partition pruning",
                                    snippet=str(node)[:100],
                                )
                            )
        return issues

    impact = (
        "Scanning unpartitioned 1B row table costs 100x more than scanning one partition. "
        "Partitioning by date reduces cost by 90-99% for time-range queries."
    )
    fix_guidance = (
        "Partition large tables by date. Most queries filter by date - partition "
        "pruning eliminates 99% of data."
    )
