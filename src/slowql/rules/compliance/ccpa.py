"""
Compliance Ccpa rules.
"""

from __future__ import annotations

import re
from typing import Any

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule

__all__ = [
    'CCPAOptOutRule',
]


class CCPAOptOutRule(ASTRule):
    """Detects queries accessing user data for sale without checking CCPA 'Do Not Sell' flag."""

    id = "COMP-CCPA-001"
    name = "Do Not Sell Flag Not Checked"
    description = (
        "Detects queries targeting marketing or third-party sharing tables that do not "
        "check the CCPA 'Do Not Sell' (DNS) flag."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_CCPA

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        if query.query_type == "SELECT" and re.search(r"marketing|sharing|third_party|affiliate", query.raw, re.IGNORECASE):
            where_cols = self._get_where_columns(ast)
            if not any(c in ("do_not_sell", "dns_flag", "opt_out", "ccpa_status") for c in where_cols):
                issues.append(
                    self.create_issue(
                        query=query,
                        message="Data share/sale query without CCPA 'Do Not Sell' flag check.",
                        snippet=query.raw[:100],
                    )
                )
        return issues

    impact = (
        "Processing 'sale' of data for consumers who have opted out violates CCPA "
        "requirements, exposing the company to statutory damages and enforcement actions."
    )
    fix_guidance = (
        "Modify all queries that share or sell data to include a check for the "
        "do_not_sell flag. Ensure it's set to FALSE before including the record."
    )
