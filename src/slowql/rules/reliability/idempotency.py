"""
Reliability Idempotency rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule

__all__ = [
    'NonIdempotentInsertRule',
    'NonIdempotentUpdateRule',
]


class NonIdempotentInsertRule(ASTRule):
    """Detects INSERT statements without idempotency guards."""

    id = "REL-IDEM-001"
    name = "Non-Idempotent INSERT Pattern"
    description = (
        "Detects INSERT statements without ON CONFLICT/ON DUPLICATE KEY or unique "
        "constraint checks, which will fail or create duplicates on retry."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_IDEMPOTENCY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Insert):
                query_upper = query.raw.upper()

                # Check for idempotency patterns
                has_on_conflict = "ON CONFLICT" in query_upper
                has_on_duplicate = "ON DUPLICATE KEY" in query_upper
                has_ignore = "INSERT IGNORE" in query_upper
                has_merge = "MERGE" in query_upper
                has_not_exists = "NOT EXISTS" in query_upper
                has_where_not_exists = "WHERE NOT EXISTS" in query_upper

                is_idempotent = any(
                    [
                        has_on_conflict,
                        has_on_duplicate,
                        has_ignore,
                        has_merge,
                        has_not_exists,
                        has_where_not_exists,
                    ]
                )

                if not is_idempotent:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="INSERT without idempotency guard — will fail or create duplicates on retry.",
                            snippet=str(node)[:100],
                        )
                    )

        return issues

    impact = (
        "Non-idempotent INSERTs cause duplicate data on network retries, application "
        "restarts, or message queue redelivery. This corrupts data and breaks business "
        "logic."
    )
    fix_guidance = (
        "Use idempotent patterns: INSERT ... ON CONFLICT DO NOTHING, INSERT IGNORE, "
        "INSERT ... ON DUPLICATE KEY UPDATE, or MERGE. Include unique identifiers (UUID) "
        "from the client."
    )


class NonIdempotentUpdateRule(ASTRule):
    """Detects UPDATE statements using non-idempotent relative operations."""

    id = "REL-IDEM-002"
    name = "Non-Idempotent UPDATE Pattern"
    description = (
        "Detects UPDATE statements using relative operations (+=, -=, counter++) "
        "without version checks, which produce different results on retry."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_IDEMPOTENCY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Update):
                # Check for relative updates (counter = counter + 1, etc.)
                for expr in node.expressions:
                    if isinstance(expr, exp.EQ):
                        right = expr.expression

                        # Check if right side contains same column (relative update)
                        if isinstance(right, (exp.Add, exp.Sub)):
                            left_col = expr.this

                            # Check if operation references the same column
                            if isinstance(left_col, exp.Column):
                                for ref in right.find_all(exp.Column):
                                    if ref.name.lower() == left_col.name.lower():
                                        # Check for version/optimistic lock
                                        query_upper = query.raw.upper()
                                        has_version_check = any(
                                            v in query_upper
                                            for v in [
                                                "VERSION",
                                                "UPDATED_AT",
                                                "MODIFIED_AT",
                                                "ETAG",
                                                "ROW_VERSION",
                                                "LOCK_VERSION",
                                            ]
                                        )

                                        if not has_version_check:
                                            issues.append(
                                                self.create_issue(
                                                    query=query,
                                                    message=f"Relative UPDATE ({left_col.name} = {left_col.name} +/- x) without version check — not idempotent.",
                                                    snippet=str(node)[:100],
                                                )
                                            )
                                        break
        return issues

    impact = (
        "Relative updates like SET count = count + 1 execute multiple times on retry, "
        "causing incorrect totals. Financial calculations become inaccurate, "
        "inventory goes negative."
    )
    fix_guidance = (
        "Use optimistic locking: UPDATE ... SET count = count + 1, version = version + 1 "
        "WHERE id = ? AND version = ?. Or use idempotency keys to track processed "
        "operations."
    )
