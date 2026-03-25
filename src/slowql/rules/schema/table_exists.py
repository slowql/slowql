from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from slowql.core.models import Dimension, RemediationMode, Severity
from slowql.rules.base import ASTRule

if TYPE_CHECKING:
    from slowql.core.models import Issue, Query
    from slowql.schema.models import Schema


class TableExistsRule(ASTRule):
    """Detects queries referencing non-existent tables."""

    id: ClassVar[str] = "SCHEMA-TBL-001"
    name: ClassVar[str] = "Non-Existent Table"
    description: ClassVar[str] = "Query references a table that does not exist in the schema"
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
        Check the query AST for non-existent tables.

        Args:
            query: The parsed query.
            ast: The sqlglot AST node.

        Returns:
            List of detected issues.
        """
        issues = []
        tables = self._get_tables(ast)

        for table_name in tables:
            if not self.schema.has_table(table_name):
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Table '{table_name}' does not exist in schema",
                        snippet=table_name,
                    )
                )

        return issues
