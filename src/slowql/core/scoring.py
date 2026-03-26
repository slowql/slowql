# slowql/src/slowql/core/scoring.py
"""
Query complexity scoring logic for SlowQL.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from sqlglot import exp

from slowql.core.models import Severity

if TYPE_CHECKING:
    from slowql.core.models import Issue, Query


class ComplexityScorer:
    """
    Calculates numerical complexity scores for SQL queries.

    The score is based on:
    1. Query structure (joins, subqueries, aggregations)
    2. Detected issues (severity-based weighting)
    """

    def __init__(self, base_score: int = 10):
        self.base_score = base_score

    def calculate_score(self, query: Query, issues: list[Issue]) -> int:
        """Calculate complexity score for a query.

        Args:
            query: The parsed query.
            issues: List of issues found in the query.

        Returns:
            Complexity score (0-100).
        """
        score = self.base_score

        # Add points for query structure
        score += self._calculate_structural_complexity(query)

        # Add points for issues
        score += self._calculate_issue_complexity(issues)

        # Cap at 100
        return min(max(score, 0), 100)

    def _calculate_structural_complexity(self, query: Query) -> int:
        """Calculate complexity based on query structure (joins, subqueries)."""
        score = 0

        # Use AST if available for more accurate analysis
        if query.ast:
            # Joins
            joins = list(query.ast.find_all(exp.Join))
            score += len(joins) * 10

            # Subqueries
            subqueries = list(query.ast.find_all(exp.Subquery))
            score += len(subqueries) * 15

            # Aggregations
            aggregations = list(query.ast.find_all(exp.AggFunc))
            score += len(aggregations) * 5
        else:
            # Fallback to simple regex if AST is not available
            joins = re.findall(r"\bJOIN\b", query.raw, re.IGNORECASE)
            score += len(joins) * 10

            subqueries = re.findall(r"\(\s*SELECT\b", query.raw, re.IGNORECASE)
            score += len(subqueries) * 15

            aggregations = re.findall(r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(", query.raw, re.IGNORECASE)
            score += len(aggregations) * 5

        return score

    def _calculate_issue_complexity(self, issues: list[Issue]) -> int:
        """Calculate complexity based on detected issues."""
        score = 0

        for issue in issues:
            if issue.severity == Severity.CRITICAL:
                score += 25
            elif issue.severity == Severity.HIGH:
                score += 15
            elif issue.severity == Severity.MEDIUM:
                score += 10
            elif issue.severity == Severity.LOW:
                score += 5
            elif issue.severity == Severity.INFO:
                score += 2
        return score


class TrendTracker:
    """Tracks query complexity scores over time to calculate trends."""

    def __init__(self, cache_dir: Path | str = ".slowql_cache"):
        self.cache_dir = Path(cache_dir)
        self.trend_file = self.cache_dir / "complexity_trends.json"
        self._trends: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        """Load trends from file."""
        if self.trend_file.exists():
            try:
                self._trends = json.loads(self.trend_file.read_text(encoding="utf-8"))
            except Exception:
                self._trends = {}

    def _save(self) -> None:
        """Save trends to file."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.trend_file.write_text(json.dumps(self._trends, indent=2), encoding="utf-8")
        except Exception:
            pass

    def get_trend(self, query_id: str, current_score: int) -> int | None:
        """
        Get trend for a query and update its stored score.

        Args:
            query_id: Unique identifier for the query (e.g., hash of normalized SQL).
            current_score: Current complexity score.

        Returns:
            Difference from last score (current - last), or None if no previous score.
        """
        last_score = self._trends.get(query_id)
        self._trends[query_id] = current_score
        self._save()

        if last_score is None:
            return None

        return current_score - last_score
