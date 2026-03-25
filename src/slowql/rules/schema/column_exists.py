from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from sqlglot import exp

from slowql.core.models import Dimension, RemediationMode, Severity
from slowql.rules.base import ASTRule

if TYPE_CHECKING:
    from slowql.core.models import Issue, Query
    from slowql.schema.models import Schema


class ColumnExistsRule(ASTRule):
    """Detects queries referencing non-existent columns."""

    id: ClassVar[str] = "SCHEMA-COL-001"
    name: ClassVar[str] = "Non-Existent Column"
    description: ClassVar[str] = "Query references a column that does not exist in the table"
    severity: ClassVar[Severity] = Severity.CRITICAL
    dimension: ClassVar[Dimension] = Dimension.RELIABILITY
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
        Check the query AST for non-existent columns.
        """
        if not self.schema:
            return []

        issues = []
        table_names = self._get_tables(ast)

        for col in ast.find_all(exp.Column):
            col_name = col.name

            # Skip wildcards and aliased columns
            if col_name == "*" or isinstance(col.parent, exp.Alias):
                continue

            table_qualifier = col.table
            if table_qualifier:
                issues.extend(self._check_qualified_column(query, col, table_qualifier))
            else:
                issues.extend(self._check_unqualified_column(query, col, table_names, ast))

        return issues

    def _check_qualified_column(self, query: Query, col: exp.Column, table_qualifier: str) -> list[Issue]:
        """Check a column that has a table qualifier."""
        assert self.schema is not None
        table = self.schema.get_table(table_qualifier)
        if table and not table.has_column(col.name):
            return [
                self.create_issue(
                    query=query,
                    message=f"Column '{col.name}' does not exist in table '{table_qualifier}'",
                    snippet=col.sql(),
                )
            ]
        return []

    def _check_unqualified_column(
        self, query: Query, col: exp.Column, table_names: list[str], ast: Any
    ) -> list[Issue]:
        """Check an unqualified column against all tables in the query."""
        assert self.schema is not None
        found = False
        valid_schema_tables = []

        for t_name in table_names:
            table = self.schema.get_table(t_name)
            if table:
                valid_schema_tables.append(t_name)
                if table.has_column(col.name):
                    found = True
                    break

        if valid_schema_tables and not found:
            # Skip if it's likely from a subquery or CTE
            if ast.find(exp.Subquery) or ast.find(exp.CTE):
                return []

            return [
                self.create_issue(
                    query=query,
                    message=f"Column '{col.name}' not found in any of the referenced tables: {', '.join(valid_schema_tables)}",
                    snippet=col.sql(),
                )
            ]
        return []
