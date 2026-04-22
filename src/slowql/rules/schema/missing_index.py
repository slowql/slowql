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
    """Detects queries filtering on unindexed columns, including JSONB operations."""

    id: ClassVar[str] = "SCHEMA-IDX-001"
    name: ClassVar[str] = "Missing Index on WHERE Column"
    description: ClassVar[str] = "Query filters on a column without an index, which may cause full table scans"
    severity: ClassVar[Severity] = Severity.MEDIUM
    dimension: ClassVar[Dimension] = Dimension.PERFORMANCE
    remediation_mode: ClassVar[RemediationMode] = RemediationMode.GUIDANCE_ONLY

    def __init__(self, schema: Schema | None = None):
        super().__init__()
        self.schema = schema

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not self.schema:
            return []

        issues = []
        where = ast.find(exp.Where)
        if not where:
            return []

        tables_in_query = ast.find_all(exp.Table)
        alias_to_table = {t.alias or t.name: t.name for t in tables_in_query}

        # Track columns already flagged via JSONB detection to avoid duplicates
        jsonb_flagged: set[tuple[str, str]] = set()

        # Check JSONB operations first (more specific, better suggestions)
        for json_extract in where.find_all(exp.JSONExtractScalar):
            jsonb_issues, flagged = self._check_jsonb_extraction(query, json_extract, alias_to_table)
            issues.extend(jsonb_issues)
            jsonb_flagged.update(flagged)

        for json_extract in where.find_all(exp.JSONExtract):
            jsonb_issues, flagged = self._check_jsonb_extraction(query, json_extract, alias_to_table)
            issues.extend(jsonb_issues)
            jsonb_flagged.update(flagged)

        # Check regular column filters (skip columns already flagged as JSONB)
        for col in where.find_all(exp.Column):
            col_name = col.name

            table_alias = col.table
            if not table_alias and len(alias_to_table) == 1:
                table_alias = next(iter(alias_to_table.keys()))

            if not table_alias:
                continue

            real_table_name = alias_to_table.get(table_alias, table_alias)

            # Skip if already flagged via JSONB detection
            if (real_table_name, col_name) in jsonb_flagged:
                continue

            table = self.schema.get_table(real_table_name)

            if table and table.has_column(col_name):
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

    def _check_jsonb_extraction(
        self,
        query: Query,
        json_node: exp.JSONExtractScalar | exp.JSONExtract,
        alias_to_table: dict[str, str],
    ) -> tuple[list[Issue], set[tuple[str, str]]]:
        """Check JSONB extraction operations for missing indexes."""
        if not self.schema:
            return [], set()

        issues = []
        flagged: set[tuple[str, str]] = set()

        column_node = json_node.this
        if not isinstance(column_node, exp.Column):
            return [], set()

        col_name = column_node.name
        table_alias = column_node.table

        if not table_alias and len(alias_to_table) == 1:
            table_alias = next(iter(alias_to_table.keys()))

        if not table_alias:
            return [], set()

        real_table_name = alias_to_table.get(table_alias, table_alias)
        table = self.schema.get_table(real_table_name)

        if not table or not table.has_column(col_name):
            return [], set()

        flagged.add((real_table_name, col_name))

        json_path_expr = json_node.expression
        json_key = None
        if isinstance(json_path_expr, exp.JSONPath):
            for path_elem in json_path_expr.expressions:
                if isinstance(path_elem, exp.JSONPathKey):
                    json_key = path_elem.this
                    break

        if not table.has_index_on([col_name]):
            fix_suggestion = f"CREATE INDEX idx_{real_table_name}_{col_name}_gin ON {real_table_name} USING GIN ({col_name});"
            if json_key:
                fix_suggestion = (
                    f"-- Option 1: GIN index for all JSONB queries\n"
                    f"CREATE INDEX idx_{real_table_name}_{col_name}_gin ON {real_table_name} USING GIN ({col_name});\n\n"
                    f"-- Option 2: B-tree index for specific key (faster for equality)\n"
                    f"CREATE INDEX idx_{real_table_name}_{col_name}_{json_key} ON {real_table_name} ((({col_name} ->> '{json_key}')));"
                )

            issues.append(
                self.create_issue(
                    query=query,
                    message=f"JSONB column '{col_name}' used in WHERE clause lacks a GIN index on table '{real_table_name}'. "
                            f"JSONB queries without indexes can cause full table scans and high I/O.",
                    snippet=json_node.sql(),
                    fix=Fix(
                        description="Add GIN index for JSONB column or expression index for specific key",
                        original="",
                        replacement=fix_suggestion,
                        confidence=FixConfidence.PROBABLE,
                    ),
                )
            )

        return issues, flagged
