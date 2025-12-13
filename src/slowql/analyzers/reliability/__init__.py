# slowql/src/slowql/analyzers/reliability/__init__.py
"""
Reliability Analyzer for SlowQL.

This analyzer focuses on data integrity, transaction safety,
and preventing catastrophic data loss events.
"""

from __future__ import annotations

from slowql.analyzers.base import RuleBasedAnalyzer
from slowql.core.models import Dimension
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
        """
        Get reliability rules from the catalog.
        
        Returns:
            List of reliability rules.
        """
        from slowql.rules.catalog import (
            DropTableRule,
            UnsafeWriteRule,
        )

        return [
            UnsafeWriteRule(),
            DropTableRule(),
        ]