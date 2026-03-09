from __future__ import annotations

"""
Cost Storage rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule

__all__ = [
    'SelectStarInETLRule',
]


class SelectStarInETLRule(ASTRule):
    """Detects SELECT * in CREATE TABLE AS SELECT (CTAS) or INSERT INTO ... SELECT."""

    id = "COST-STORAGE-001"
    name = "SELECT * in ETL/CTAS Queries"
    description = (
        "Detects SELECT * in CREATE TABLE AS SELECT (CTAS), INSERT INTO ... SELECT, "
        "or other data persistence patterns. This copies unnecessary columns into "
        "storage, inflating storage and backup costs."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_STORAGE

    def _has_select_star(self, select_node: Any) -> bool:
        if hasattr(select_node, "expressions"):
            for expr in select_node.expressions:
                if isinstance(expr, exp.Star):
                    return True
        return False

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            is_ctas = isinstance(node, exp.Create) and getattr(node, "kind", "") == 'TABLE'
            is_insert = isinstance(node, exp.Insert)

            if is_ctas or is_insert:
                select = getattr(node, "expression", None)
                if select and isinstance(select, exp.Select):
                    if self._has_select_star(select):
                        issues.append(
                            self.create_issue(
                                query=query,
                                message="SELECT * in persistence query detected.",
                                snippet=str(node)[:100],
                                impact=(
                                    "Storing unnecessary columns increases storage costs linearly with row count. "
                                    "In columnar stores (Redshift, Snowflake), this also increases metadata "
                                    "overhead and backup costs."
                                ),
                                fix=Fix(
                                    description="Explicitly list columns",
                                    replacement="",
                                    is_safe=False,
                                ),
                            )
                        )
        return issues
