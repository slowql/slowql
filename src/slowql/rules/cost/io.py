from __future__ import annotations

"""
Cost Io rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule

__all__ = [
    'RedundantOrderByRule',
]


class RedundantOrderByRule(ASTRule):
    """Detects ORDER BY clauses inside subqueries where the outer query doesn't use LIMIT."""

    id = "COST-IO-001"
    name = "Redundant ORDER BY in Subqueries"
    description = (
        "Detects ORDER BY clauses inside subqueries where the outer query re-sorts "
        "or doesn't use ordering. Sorting is expensive (disk I/O for temp tables) "
        "and wasteful if results are re-sorted."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_IO

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Subquery):
                inner_select = getattr(node, "this", None)
                if isinstance(inner_select, exp.Select):
                    args = getattr(inner_select, "args", {})
                    if args.get('order'):
                        has_limit = args.get('limit') is not None
                        if not has_limit:
                            issues.append(
                                self.create_issue(
                                    query=query,
                                    message="Redundant ORDER BY in subquery detected.",
                                    snippet=str(inner_select)[:100],
                                    impact=(
                                        "Unnecessary sorting forces the database to write intermediate results to "
                                        "disk (tempdb). In cloud databases, this increases I/O costs and can exhaust "
                                        "allocated IOPS, throttling queries."
                                    ),
                                    fix=Fix(
                                        description="Remove ORDER BY from subquery",
                                        replacement="",
                                        is_safe=False,
                                    ),
                                )
                            )
        return issues
