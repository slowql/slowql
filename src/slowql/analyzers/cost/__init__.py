# slowql/src/slowql/analyzers/cost/__init__.py
"""
Cost Analyzer for SlowQL.

This analyzer estimates the financial impact of queries, particularly
for cloud data warehouses (Snowflake, BigQuery) and provisioned databases.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slowql.analyzers.base import BaseAnalyzer
from slowql.core.models import (
    Dimension,
    Issue,
    Severity,
)

if TYPE_CHECKING:
    from slowql.core.config import Config
    from slowql.core.models import Query
    from slowql.rules.base import Rule


class CostAnalyzer(BaseAnalyzer):
    """
    Analyzer for cost estimation.
    
    Unlike rule-based analyzers, this uses heuristics to estimate
    compute/scan costs based on the query structure and (optional)
    cloud provider configuration.
    """

    name = "cost"
    dimension = Dimension.COST
    description = "Estimates cloud cost and resource consumption."
    priority = 50

    def get_rules(self) -> list[Rule]:
        """
        Cost analyzer doesn't use standard rules yet, but heuristic models.
        Returning empty list as it implements analyze directly.
        """
        return []

    def analyze(
        self,
        query: Query,
        *,
        config: Config | None = None,
    ) -> list[Issue]:
        """
        Analyze query for cost implications.
        """
        issues: list[Issue] = []
        
        # Ensure query.raw is not None before string operations
        raw_sql = query.raw or ""
        raw_lower = raw_sql.lower()

        # Check if query is a SELECT statement using the property or explicit check
        is_select = False
        if hasattr(query, "is_select"):
            is_select = query.is_select
        elif query.query_type:
            is_select = query.query_type.upper() == "SELECT"

        # Simple heuristic: Scanning * without limit in aggregate
        # This is a basic example; a real implementation would estimate bytes scanned
        if is_select and "count" in raw_lower and "where" not in raw_lower:
            issues.append(Issue(
                rule_id="COST-COMP-002",
                message="Unfiltered aggregation on potential full table.",
                severity=Severity.LOW,
                dimension=Dimension.COST,
                location=query.location,
                snippet=raw_sql[:50],
                impact="High compute cost for aggregation over entire dataset.",
                fix=None,
                category=None
            ))

        return issues