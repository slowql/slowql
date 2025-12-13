# slowql/src/slowql/analyzers/quality/__init__.py
"""
Quality Analyzer for SlowQL.

This analyzer focuses on code maintainability, readability, and
adherence to modern SQL best practices.
"""

from __future__ import annotations

from slowql.analyzers.base import RuleBasedAnalyzer
from slowql.core.models import Dimension
from slowql.rules.base import Rule


class QualityAnalyzer(RuleBasedAnalyzer):
    """
    Analyzer for SQL code quality.
    
    Checks for:
    - Deprecated syntax
    - Readability issues
    - Maintainability anti-patterns
    """

    name = "quality"
    dimension = Dimension.QUALITY
    description = "Enforces SQL coding standards and best practices."
    priority = 40

    def get_rules(self) -> list[Rule]:
        """
        Get quality rules from the catalog.
        """
        from slowql.rules.catalog import ImplicitJoinRule

        return [
            ImplicitJoinRule(),
        ]