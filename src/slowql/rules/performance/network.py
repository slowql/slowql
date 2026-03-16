"""
Performance Network rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, Rule

__all__ = [
    "ExcessiveColumnCountRule",
    "LargeObjectUnboundedRule",
    "MissingSetNocountRule",
]


class ExcessiveColumnCountRule(ASTRule):
    """Detects SELECT statements with more than 20 explicit columns."""

    id = "PERF-NET-001"
    name = "Excessive Column Count in SELECT"
    description = "Detects SELECT statements with more than 20 explicit columns."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_NETWORK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Select):
                columns = getattr(node, "expressions", [])

                if any(isinstance(c, exp.Star) for c in columns):
                    continue

                if len(columns) > 20:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"SELECT with {len(columns)} columns - consider reducing or using separate queries",
                            snippet=str(node)[:100],
                            impact=(
                                "Wide result sets waste network bandwidth, consume more memory on both server and client, "
                                "and often indicate missing projection."
                            ),
                            fix=Fix(
                                description="Select only needed columns. Use DTOs/projections in application layer.",
                                replacement="",
                                is_safe=False,
                            ),
                        )
                    )

        return issues


class LargeObjectUnboundedRule(ASTRule):
    """Detects SELECT of BLOB/CLOB/TEXT columns without WHERE clause."""

    id = "PERF-NET-002"
    name = "Large Object Column in Non-Filtered Query"
    description = "Detects SELECT of BLOB/CLOB/TEXT columns without WHERE clause, potentially transferring massive data."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_NETWORK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        blob_columns = {
            "blob",
            "clob",
            "text",
            "content",
            "body",
            "data",
            "image",
            "document",
            "file",
            "attachment",
            "payload",
            "binary",
        }

        for node in ast.walk():
            if isinstance(node, exp.Select):
                has_where = node.args.get("where") is not None
                has_limit = node.args.get("limit") is not None

                if not has_where and not has_limit:
                    for col in getattr(node, "expressions", []):
                        if isinstance(col, exp.Column):
                            col_name = getattr(col, "name", "").lower()
                            if any(bc in col_name for bc in blob_columns):
                                issues.append(
                                    self.create_issue(
                                        query=query,
                                        message=f"Unbounded SELECT of large object column '{col.name}'",
                                        snippet=str(node)[:100],
                                        impact=(
                                            "Selecting BLOB columns without filtering can transfer gigabytes of data. "
                                            "Each BLOB read may hit slow storage. This crashes applications and saturates networks."
                                        ),
                                        fix=Fix(
                                            description="Exclude large columns from general queries. Fetch BLOB data separately by ID when needed.",
                                            replacement="",
                                            is_safe=False,
                                        ),
                                    )
                                )

        return issues


class MissingSetNocountRule(Rule):
    """Detects T-SQL stored procedures without SET NOCOUNT ON."""

    id = "PERF-TSQL-001"
    name = "Missing SET NOCOUNT ON"
    description = (
        "T-SQL stored procedures without SET NOCOUNT ON send row count "
        "messages for every DML statement back to the client, generating "
        "unnecessary network traffic and interfering with some ORMs and "
        "client libraries."
    )
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_NETWORK
    dialects = ("tsql",)

    impact = (
        "Each INSERT, UPDATE, DELETE inside the procedure sends a 'N rows "
        "affected' message to the client. This adds network overhead and can "
        "cause ADO.NET and other drivers to misinterpret result sets."
    )
    fix_guidance = (
        "Add SET NOCOUNT ON as the first statement in every stored procedure "
        "and trigger. This is a universal T-SQL best practice."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bCREATE\s+(?:OR\s+ALTER\s+)?PROC(?:EDURE)?\b"):
            return []
        raw_upper = query.raw.upper()
        if "SET NOCOUNT ON" in raw_upper:
            return []
        return [
            self.create_issue(
                query=query,
                message="Stored procedure without SET NOCOUNT ON — unnecessary network overhead.",
                snippet=query.raw[:80],
            )
        ]
