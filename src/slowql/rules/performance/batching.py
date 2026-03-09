from __future__ import annotations

"""
Performance Batching rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'LargeUnbatchedOperationRule',
    'MissingBatchSizeInLoopRule',
]


class LargeUnbatchedOperationRule(ASTRule):
    """Detects UPDATE/DELETE without WHERE clause or row limit."""

    id = "PERF-BATCH-001"
    name = "Large Unbatched Operation"
    description = "Detects UPDATE/DELETE without WHERE clause or row limit, affecting entire tables."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_BATCH

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, (exp.Update, exp.Delete)):
                query_upper = query.raw.upper()
                has_limit = 'TOP' in query_upper or 'LIMIT' in query_upper

                if not has_limit:
                    stmt_type = 'UPDATE' if isinstance(node, exp.Update) else 'DELETE'
                    issues.append(self.create_issue(
                        query=query,
                        message=f"Unbatched {stmt_type} without WHERE clause - affects entire table",
                        snippet=str(node)[:100],
                        impact=(
                            "Unbatched mass operations generate massive transaction logs, hold locks for extended periods, "
                            "and can fill disk. A single DELETE can lock a table for hours."
                        ),
                        fix=Fix(
                            description="Process in batches using TOP/LIMIT and loops. Use WAITFOR DELAY between batches.",
                            replacement="",
                            is_safe=False,
                        ),
                    ))

        return issues


class MissingBatchSizeInLoopRule(PatternRule):
    """Detects WHILE loops with UPDATE/DELETE that don't specify TOP/LIMIT."""

    id = "PERF-BATCH-002"
    name = "Missing Batch Size in Loop"
    description = "Detects WHILE loops with UPDATE/DELETE that don't specify TOP/LIMIT."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_BATCH

    pattern = r"\bWHILE\b[\s\S]*?\b(UPDATE|DELETE)\b(?![\s\S]*?\b(TOP|LIMIT)\b)[\s\S]*?\bEND\b"
    message_template = "WHILE loop with unbatched DML detected."

    impact = (
        "WHILE loops without batch limits may process unlimited rows per iteration, "
        "negating the benefits of batching."
    )
    fix_guidance = "Always use TOP/LIMIT in batched operations inside loops."
