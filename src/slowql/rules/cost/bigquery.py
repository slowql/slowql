"""BigQuery-specific cost rules."""
from __future__ import annotations

import re
from typing import ClassVar

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = ["BigQueryMissingLimitRule", "BigQueryRepeatedSubqueryRule", "BigQuerySelectStarCostRule"]

class BigQuerySelectStarCostRule(PatternRule):
    """Detects SELECT * in BigQuery which scans all columns."""

    id = "COST-BQ-001"
    name = "SELECT * in BigQuery Scans All Columns"
    dialects: ClassVar[tuple[str, ...]] = ("bigquery",)
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    pattern = r"\bSELECT\s+\*"
    message_template = "SELECT * in BigQuery scans all columns — billed by bytes scanned: {match}"
    impact = (
        "BigQuery charges per byte scanned. SELECT * on a 1TB table with 50 columns "
        "costs 50x more than selecting only the 1 column you need. "
        "At $5/TB, a daily job doing SELECT * can cost thousands per month unnecessarily."
    )
    fix_guidance = (
        "Always specify only the columns you need. "
        "Use column pruning: SELECT id, name, date FROM table. "
        "Partition and cluster tables on frequently filtered columns to reduce scan cost."
    )

class BigQueryMissingLimitRule(PatternRule):
    """Detects queries without LIMIT in BigQuery."""

    id = "COST-BQ-002"
    name = "BigQuery Query Without LIMIT"
    dialects: ClassVar[tuple[str, ...]] = ("bigquery",)
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    pattern = r"\bSELECT\b(?![\s\S]*\bLIMIT\b)"
    message_template = "SELECT without LIMIT in BigQuery — full table scan billed: {match}"
    impact = (
        "BigQuery bills for bytes scanned regardless of rows returned. "
        "An exploratory query without LIMIT on a large table incurs full scan cost "
        "even if you only need a sample of the data."
    )
    fix_guidance = (
        "Add LIMIT for exploratory queries: SELECT * FROM t LIMIT 1000. "
        "Use table previews in the console for sampling. "
        "Use _PARTITIONTIME or _PARTITIONDATE filters to limit scan range."
    )


class BigQueryRepeatedSubqueryRule(Rule):
    """Detects repeated subqueries that should be CTEs in BigQuery."""

    id = "COST-BQ-003"
    name = "Repeated Subquery Instead of CTE"
    description = "Repeating the same subquery scans data multiple times — use CTEs."
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("bigquery",)
    impact = "Each repeated subquery scans underlying tables again, multiplying cost."
    fix_guidance = "Extract into WITH (CTE) clause. BigQuery materializes CTEs referenced multiple times."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        matches = re.findall(r"\(\s*SELECT\s+", query.raw, re.IGNORECASE)
        if len(matches) < 2:
            return []
        raw_upper = query.raw.upper()
        if "WITH" in raw_upper and "AS" in raw_upper:
            return []
        return [self.create_issue(query=query, message=f"Query contains {len(matches)} subqueries — consider CTEs to reduce bytes scanned.", snippet=query.raw[:80])]
