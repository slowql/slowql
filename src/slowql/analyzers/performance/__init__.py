# slowql/src/slowql/analyzers/performance/__init__.py
"""
Performance Analyzer for SlowQL.

This analyzer focuses on detecting query patterns that cause poor
performance, high resource usage, or scalability issues.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slowql.analyzers.base import RuleBasedAnalyzer
from slowql.core.models import Dimension
from slowql.rules.catalog import (
    DistinctOnLargeSetRule,
    LeadingWildcardRule,
    MissingWhereRule,
    SelectStarRule,
)

if TYPE_CHECKING:
    from slowql.rules.base import Rule

class PerformanceAnalyzer(RuleBasedAnalyzer):
    """
    Analyzer for performance optimization.

    Checks for:
    - Index usage inhibitors (SARGability)
    - Full table scan indicators
    - Expensive operations (Sorts, joins)
    """

    name = "performance"
    dimension = Dimension.PERFORMANCE
    description = "Detects anti-patterns that degrade query speed and scalability."
    priority = 20

    def get_rules(self) -> list[Rule]:
        """
        Get performance rules from the catalog.

        Returns:
            List of performance rules.
        """
        return [
            SelectStarRule(),
            LeadingWildcardRule(),
            MissingWhereRule(),
            DistinctOnLargeSetRule(),
        ]
