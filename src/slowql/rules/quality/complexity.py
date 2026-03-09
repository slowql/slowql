from __future__ import annotations

"""
Quality Complexity rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'CyclomaticComplexityRule',
    'ExcessiveCaseNestingRule',
    'ExcessiveSubqueryNestingRule',
    'GodQueryRule',
    'LongQueryRule',
]


class ExcessiveCaseNestingRule(ASTRule):
    """Detects CASE expressions nested more than 3 levels deep."""

    id = "QUAL-COMPLEX-001"
    name = "Excessive CASE Nesting"
    description = (
        "Detects CASE expressions nested more than 3 levels deep, which are hard to read, test, and maintain."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_COMPLEXITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        def get_case_depth(node):
            if not isinstance(node, exp.Case):
                return 0
            max_inner = 0
            for child in node.walk():
                if child is node:
                    continue
                if isinstance(child, exp.Case):
                    inner_depth = get_case_depth(child)
                    max_inner = max(max_inner, inner_depth)
            return 1 + max_inner

        for node in ast.walk():
            if isinstance(node, exp.Case):
                # Only check top-level CASE nodes
                parent = getattr(node, 'parent', None)
                is_nested = False
                while parent:
                    if isinstance(parent, exp.Case):
                        is_nested = True
                        break
                    parent = getattr(parent, 'parent', None)

                if not is_nested:
                    depth = get_case_depth(node)
                    if depth > 3:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"CASE expression nested {depth} levels deep",
                                snippet=str(node)[:100],
                            )
                        )
        return issues

    impact = (
        "Deeply nested CASE statements are difficult to understand, test, and debug. Each nesting level "
        "doubles the cognitive load. Often indicates business logic that belongs in application layer."
    )
    fix_guidance = (
        "Refactor to lookup table or create a user-defined function. Limit CASE to 2-3 levels maximum. "
        "Use early returns in functions."
    )


class ExcessiveSubqueryNestingRule(ASTRule):
    """Detects subqueries nested more than 3 levels deep."""

    id = "QUAL-COMPLEX-002"
    name = "Excessive Subquery Nesting"
    description = (
        "Detects subqueries nested more than 3 levels deep, indicating overly complex query structure."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_COMPLEXITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        def get_subquery_depth(node):
            if not isinstance(node, exp.Subquery):
                return 0
            max_inner = 0
            for child in node.walk():
                if child is node:
                    continue
                if isinstance(child, exp.Subquery):
                    inner_depth = get_subquery_depth(child)
                    max_inner = max(max_inner, inner_depth)
            return 1 + max_inner

        for node in ast.walk():
            if isinstance(node, exp.Subquery):
                # Avoid redundant issues for nested subqueries
                parent = getattr(node, 'parent', None)
                is_nested = False
                while parent:
                    if isinstance(parent, exp.Subquery):
                        is_nested = True
                        break
                    parent = getattr(parent, 'parent', None)

                if not is_nested:
                    depth = get_subquery_depth(node)
                    if depth >= 3:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"Subquery nested {depth} levels deep",
                                snippet=str(node)[:100],
                            )
                        )
        return issues

    impact = (
        "Deeply nested subqueries are unreadable and hard to optimize. Each level makes query execution "
        "unpredictable. Often indicates poor query design that should use CTEs or temp tables."
    )
    fix_guidance = (
        "Use Common Table Expressions (CTEs) to flatten query structure. Or break into temp tables. "
        "Maximum 2-3 levels for readability."
    )


class GodQueryRule(ASTRule):
    """Detects "god queries" with excessive clauses."""

    id = "QUAL-COMPLEX-003"
    name = "God Query"
    description = (
        "Detects queries with excessive clauses (10+ JOINs, complex WHERE, GROUP BY, HAVING, ORDER BY)."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_COMPLEXITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Select):
                complexity_score = 0

                # Count JOINs
                joins = node.args.get('joins') or []
                complexity_score += len(joins) * 2

                # WHERE clause complexity
                where = node.args.get('where')
                if where:
                    complexity_score += 1
                    where_str = str(where).upper()
                    complexity_score += where_str.count(' AND ')
                    complexity_score += where_str.count(' OR ')

                # GROUP BY, HAVING, ORDER BY
                if node.args.get('group'):
                    complexity_score += 2
                if node.args.get('having'):
                    complexity_score += 2
                if node.args.get('order'):
                    complexity_score += 1

                # Subqueries
                subquery_count = len(list(node.find_all(exp.Subquery)))
                complexity_score += subquery_count * 3

                if complexity_score > 25:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"God query detected (complexity score: {complexity_score}) - break into smaller, focused queries",
                            snippet=str(node)[:100],
                        )
                    )

        return issues

    impact = (
        "God queries try to do everything in one statement. They're slow, hard to optimize, impossible "
        "to test, and unmaintainable. Often leads to unpredictable performance."
    )
    fix_guidance = (
        "Break into multiple focused queries. Use temp tables for intermediate results. Separate "
        "data retrieval from business logic. Aim for < 5 JOINs per query."
    )


class CyclomaticComplexityRule(PatternRule):
    """Detects stored procedures with high cyclomatic complexity."""

    id = "QUAL-COMPLEX-004"
    name = "Cyclomatic Complexity in Stored Procedure"
    description = (
        "Detects stored procedures with high cyclomatic complexity (many IF/WHILE/CASE branches)."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_COMPLEXITY

    pattern = r'\b(CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE|CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION)\b[\s\S]*?(?:(?:\bIF\b|\bWHILE\b|\bCASE\b)[\s\S]*?){5,}'

    impact = (
        "High cyclomatic complexity means many code paths, making testing exponentially harder. "
        "Bugs hide in untested branches. Overly complex logic is hard to maintain."
    )
    fix_guidance = (
        "Extract complex logic into smaller functions. Use lookup tables instead of IF chains. "
        "Limit to 10 branches per procedure. Aim for cyclomatic complexity < 10."
    )


class LongQueryRule(Rule):
    """Detects queries longer than 50 lines."""

    id = "QUAL-COMPLEX-005"
    name = "Long Query (Line Count)"
    description = "Detects queries longer than 50 lines, suggesting over-complexity."
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_COMPLEXITY

    def check(self, query: Query) -> list[Issue]:
        issues = []
        line_count = query.raw.count('\n') + 1

        if line_count > 50:
            issues.append(
                self.create_issue(
                    query=query,
                    message=f"Query is {line_count} lines long - consider breaking into smaller queries or using CTEs",
                    snippet=query.raw[:100],
                )
            )

        return issues

    impact = (
        "Queries over 50 lines are hard to understand, review, and debug. Often indicates poor "
        "separation of concerns or missing abstraction layers."
    )
    fix_guidance = (
        "Break into multiple queries or CTEs. Use views for complex joins. Extract repeated "
        "patterns into functions. Aim for queries under 30 lines."
    )
