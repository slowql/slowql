# slowql/src/slowql/analyzers/reliability/__init__.py
"""
Reliability Analyzer for SlowQL.

This analyzer focuses on data integrity, transaction safety,
and preventing catastrophic data loss events.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slowql.analyzers.base import RuleBasedAnalyzer
from slowql.core.models import Dimension

if TYPE_CHECKING:
    from slowql.rules.base import Rule


class ReliabilityAnalyzer(RuleBasedAnalyzer):
    """
    Analyzer for database reliability and safety.

    Checks for:
    - Destructive operations without safeguards
    - Schema integrity risks
    - Transaction boundaries
    """

    name = "reliability"
    dimension = Dimension.RELIABILITY
    description = "Safeguards against data loss and destructive operations."
    priority = 15  # High priority, just after security

    def get_rules(self) -> list[Rule]:
        """Load ALL reliability rules from catalog (19 rules)."""
        from slowql.rules.catalog import get_rules_by_dimension
        return get_rules_by_dimension(self.dimension.value)
