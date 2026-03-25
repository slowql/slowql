from __future__ import annotations

from typing import TYPE_CHECKING

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Severity
from slowql.rules.base import Rule

if TYPE_CHECKING:
    from slowql.core.models import AnalysisResult, Query


class CrossFileBreakingChangeRule(Rule):
    """
    Detects if a DDL change in one file breaks queries in other files.
    """

    id = "SCH-BRK-001"
    name = "Cross-File Breaking Change"
    description = (
        "Detects destructive changes (DROP, ALTER DROP) that break queries "
        "defined in other files of the project."
    )
    severity = Severity.HIGH
    dimension = Dimension.SCHEMA
    category = Category.REL_DATA_INTEGRITY

    def check(self, query: Query) -> list[Issue]:
        """
        Standard check method. For cross-file analysis,
        individual query checks don't have enough context,
        so we do nothing here and use check_project instead.
        """
        return []

    def _extract_dropped_objects(self, ast: exp.Expression) -> tuple[list[str], dict[str, list[str]]]:
        """Extract dropped tables and columns from the AST."""
        dropped_tables: list[str] = []
        dropped_columns: dict[str, list[str]] = {}

        # Handle DROP TABLE
        for drop in ast.find_all(exp.Drop):
            if isinstance(drop.this, exp.Table):
                dropped_tables.append(drop.this.name)

        # Handle ALTER TABLE DROP COLUMN
        for alter in ast.find_all(exp.Alter):
            table_node = alter.find(exp.Table)
            if table_node and table_node.name:
                table_name = table_node.name
                for action in alter.args.get("actions", []):
                    if isinstance(action, exp.Drop) and isinstance(action.this, exp.Column):
                        dropped_columns.setdefault(table_name, []).append(action.this.name)
                    elif hasattr(action, "kind") and str(action.kind).upper() == "DROP":
                        if hasattr(action, "this") and isinstance(action.this, exp.Column):
                            dropped_columns.setdefault(table_name, []).append(action.this.name)

        return dropped_tables, dropped_columns

    def check_project(self, result: AnalysisResult) -> list[Issue]:
        """
        Check all queries in the project for breakages caused by DDL queries.
        """
        issues: list[Issue] = []
        all_queries = result.queries

        # 1. Identify all DDL queries that drop or alter objects
        breaking_queries = [q for q in all_queries if q.is_ddl]

        for ddl_query in breaking_queries:
            if not ddl_query.ast:
                continue

            dropped_tables, dropped_columns = self._extract_dropped_objects(ddl_query.ast)

            # 2. Check all OTHER queries for references to these dropped objects
            for other_query in all_queries:
                if other_query == ddl_query:
                    continue

                # Check tables
                for ref_table_name in other_query.tables:
                    if ref_table_name in dropped_tables:
                        issues.append(self.create_issue(
                            query=ddl_query,
                            message=f"Breaking Change: Dropping table '{ref_table_name}' breaks query in {other_query.location.file or 'another file'}.",
                            snippet=ddl_query.raw,
                            impact=f"The query at {other_query.location} will fail.",
                            metadata={"broken_file": other_query.location.file, "broken_line": other_query.location.line}
                        ))

                # Check columns
                for table, dropped_cols in dropped_columns.items():
                    if table in other_query.tables:
                        for col in other_query.columns:
                            if col in dropped_cols:
                                issues.append(self.create_issue(
                                    query=ddl_query,
                                    message=f"Breaking Change: Dropping column '{table}.{col}' breaks query in {other_query.location.file or 'another file'}.",
                                    snippet=ddl_query.raw,
                                    impact=f"The query at {other_query.location} will fail.",
                                    metadata={"broken_file": other_query.location.file, "broken_line": other_query.location.line}
                                ))

        return issues
