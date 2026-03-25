from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import Rule
from slowql.schema.models import Schema


class BreakingChangeRule(Rule):
    """
    Detects if a migration makes a change that breaks existing schema state.
    """

    id = "MIG-001"
    name = "Breaking Schema Change"
    description = (
        "Detects destructive changes (DROP TABLE, DROP COLUMN) that may break "
        "existing application code or subsequent migrations."
    )
    severity = Severity.HIGH
    dimension = Dimension.MIGRATION
    category = Category.REL_DATA_INTEGRITY

    def __init__(self, schema_before: Schema) -> None:
        self.schema_before = schema_before

    def check(self, query: Query) -> list[Issue]:
        # This rule is special because it compares query against previous schema
        # DDLParser already handles the 'is it a drop' logic, but here we provide the warning

        # We look for DROP statements in the query
        ast = query.ast
        if not ast:
            return []

        from sqlglot import exp

        issues = []

        # Handle DROP TABLE
        for drop in ast.find_all(exp.Drop):
            if isinstance(drop.this, exp.Table):
                table_name = drop.this.name
                if self.schema_before.has_table(table_name):
                    issues.append(self.create_issue(
                        query=query,
                        message=f"Breaking Change: Dropping table '{table_name}' which exists in the schema.",
                        snippet=query.raw,
                        impact="Will cause immediate failure of any query referencing this table.",
                    ))

        # Handle ALTER TABLE DROP COLUMN
        for alter in ast.find_all(exp.Alter):
            table_node = alter.find(exp.Table)
            if not table_node or not table_node.name:
                continue

            table_name = table_node.name
            if not self.schema_before.has_table(table_name):
                continue

            table_before = self.schema_before.get_table(table_name)

            for action in alter.args.get("actions", []):
                if isinstance(action, exp.Drop) and isinstance(action.this, exp.Column):
                    col_name = action.this.name
                    if table_before.has_column(col_name):
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Breaking Change: Dropping column '{col_name}' from table '{table_name}'.",
                            snippet=query.raw,
                            impact=f"Queries referencing {table_name}.{col_name} will fail.",
                        ))
                elif hasattr(action, 'kind') and str(action.kind).upper() == 'DROP':
                     if hasattr(action, 'this') and isinstance(action.this, exp.Column):
                        col_name = action.this.name
                        if table_before.has_column(col_name):
                            issues.append(self.create_issue(
                                query=query,
                                message=f"Breaking Change: Dropping column '{col_name}' from table '{table_name}'.",
                                snippet=query.raw,
                                impact=f"Queries referencing {table_name}.{col_name} will fail.",
                            ))

        return issues
