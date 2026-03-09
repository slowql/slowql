from __future__ import annotations

"""
Quality Testing rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'HardcodedTestDataRule',
    'NonDeterministicQueryRule',
    'OrderByMissingForPaginationRule',
]


class NonDeterministicQueryRule(ASTRule):
    """Detects queries that might return different results (e.g., using NOW())."""

    id = "QUAL-TEST-001"
    name = "Non-Deterministic Query"
    description = "Detects queries using non-deterministic functions (NOW, RAND) in filters/logic."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_TESTING

    NON_DET = {'NOW', 'RAND', 'RANDOM', 'CURRENT_TIMESTAMP', 'GETDATE', 'CLOCK_TIMESTAMP'}

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for func in ast.find_all(exp.Anonymous):
            if str(func.this).upper() in self.NON_DET:
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Non-deterministic function '{str(func.this).upper()}' detected - makes testing difficult",
                        snippet=str(func),
                    )
                )
        return issues

    impact = (
        "Non-deterministic queries are hard to test and reproduce. They can cause flaky tests "
        "and unpredictable behavior in production if results depend on the exact millisecond of execution."
    )
    fix_guidance = (
        "Pass time as a parameter from the application layer. Use fixed seeds for random functions. "
        "Ensure query results are predictable for the same input state."
    )


class OrderByMissingForPaginationRule(ASTRule):
    """Detects LIMIT/OFFSET without ORDER BY."""

    id = "QUAL-TEST-002"
    name = "Pagination Without ORDER BY"
    description = "Detects LIMIT/OFFSET usage without an explicit ORDER BY clause."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_TESTING

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for select in ast.find_all(exp.Select):
            if (select.args.get('limit') or select.args.get('offset')) and not select.args.get('order'):
                issues.append(
                    self.create_issue(
                        query=query,
                        message="Pagination (LIMIT/OFFSET) used without ORDER BY - result order is non-deterministic",
                        snippet=str(select)[:100],
                    )
                )
        return issues

    impact = (
        "SQL does not guarantee row order without ORDER BY. Without it, pagination can return "
        "the same row on multiple pages or skip rows entirely, leading to UI bugs."
    )
    fix_guidance = (
        "Always add ORDER BY when using LIMIT/OFFSET. Ensure the sort key is unique (e.g., include ID) "
        "to guarantee stable sorting."
    )


class HardcodedTestDataRule(PatternRule):
    """Detects obvious test data in queries (e.g., 'test%', 'dummy')."""

    id = "QUAL-TEST-003"
    name = "Hardcoded Test Data"
    description = "Detects obvious test data patterns (test, dummy, fake, temp, asdf, qwerty) in queries."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_TESTING

    pattern = r'[\'"][^\'"]*(test|dummy|fake|temp|asdf|qwerty)[^\'"]*[\'"]'

    impact = (
        "Leftover test data markers in production queries indicate poor release hygiene. "
        "They can accidentally filter out real data or expose test logic to users."
    )
    fix_guidance = (
        "Remove test data filters from production queries. Use proper environment "
        "configuration to separate test and production logic."
    )
