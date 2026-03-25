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

        Args:
            query: The parsed query.
            ast: The sqlglot AST node.

        Returns:
            List of detected issues.
        """
        issues = []

        # Get all base tables referenced in the query to handle unqualified columns
        table_names = self._get_tables(ast)

        for col in ast.find_all(exp.Column):
            col_name = col.name

            # Skip wildcards (SELECT *)
            if col_name == "*":
                continue

            # Skip validation for aliased columns in the SELECT list (complex to resolve)
            # In sqlglot, an aliased column in SELECT usually looks like Alias(this=Column, alias=...)
            if isinstance(col.parent, exp.Alias):
                continue

            # Handle qualified columns (e.g., users.email)
            table_qualifier = col.table

            if table_qualifier:
                # Check specific table from schema
                table = self.schema.get_table(table_qualifier)
                if table:
                    if not table.has_column(col_name):
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"Column '{col_name}' does not exist in table '{table_qualifier}'",
                                snippet=col.sql(),
                            )
                        )
                # If table doesn't exist in schema, we let TableExistsRule handle it or skip
            else:
                # Unqualified column: check all tables referenced in the query
                found = False
                valid_schema_tables = []

                for t_name in table_names:
                    table = self.schema.get_table(t_name)
                    if table:
                        valid_schema_tables.append(t_name)
                        if table.has_column(col_name):
                            found = True
                            break

                # If we have known tables in the query but none contain the column, flag it
                # Note: This might have false positives if columns come from subqueries/CTEs
                # which are not yet fully supported by this simple resolver.
                if valid_schema_tables and not found:
                    # Skip if it's likely from a subquery or CTE (if query has them)
                    if ast.find(exp.Subquery) or ast.find(exp.CTE):
                        continue

                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"Column '{col_name}' not found in any of the referenced tables: {', '.join(valid_schema_tables)}",
                            snippet=col.sql(),
                        )
                    )

        return issues
