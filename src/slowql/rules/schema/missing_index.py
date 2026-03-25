from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from sqlglot import exp

from slowql.core.models import (
    Dimension,
    Fix,
    FixConfidence,
    RemediationMode,
    Severity,
)
from slowql.rules.base import ASTRule

if TYPE_CHECKING:
    from slowql.core.models import Issue, Query
    from slowql.schema.models import Schema


class MissingIndexRule(ASTRule):
    """Detects queries filtering on unindexed columns."""

    id: ClassVar[str] = "SCHEMA-IDX-001"
    name: ClassVar[str] = "Missing Index on WHERE Column"
    description: ClassVar[str] = "Query filters on a column without an index, which may cause full table scans"
    severity: ClassVar[Severity] = Severity.MEDIUM
    dimension: ClassVar[Dimension] = Dimension.PERFORMANCE
    remediation_mode: ClassVar[RemediationMode] = RemediationMode.GUIDANCE_ONLY

    def __init__(self, schema: Schema | None = None):
        """
        Initialize the rule.

        Args:
            schema: The database schema to validate against.
        """
        super().__init__()
        self.schema = schema

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        """
        Check the query AST for columns in WHERE clauses without indexes.

        Args:
            query: The parsed query.
            ast: The sqlglot AST node.

        Returns:
            List of detected issues.
        """
        issues = []
        where = ast.find(exp.Where)
        if not where:
            return []

        # Map aliases to table names in the query
        tables_in_query = ast.find_all(exp.Table)
        alias_to_table = {t.alias or t.name: t.name for t in tables_in_query}

        for col in where.find_all(exp.Column):
            col_name = col.name

            # Identify the table for this column
            table_alias = col.table
            if not table_alias and len(alias_to_table) == 1:
                # If only one table, it must be the one
                table_alias = next(iter(alias_to_table.keys()))

            if not table_alias:
                # Could be complex (multiple tables, no qualifier)
                # For now, we skip if we can't unambiguously identify the table
                continue

            real_table_name = alias_to_table.get(table_alias, table_alias)
            table = self.schema.get_table(real_table_name)

            if table and table.has_column(col_name):
                # Check if an index exists on this column
                if not table.has_index_on([col_name]):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"Column '{col_name}' used in WHERE clause lacks an index on table '{real_table_name}'",
                            snippet=col.sql(),
                            fix=Fix(
                                description=f"Consider adding an index on {real_table_name}({col_name})",
                                original="",
                                replacement=f"CREATE INDEX idx_{real_table_name}_{col_name} ON {real_table_name}({col_name});",
                                confidence=FixConfidence.PROBABLE,
                            ),
                        )
                    )

        return issues
