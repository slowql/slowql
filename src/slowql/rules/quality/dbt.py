# slowql/src/slowql/rules/quality/dbt.py
from __future__ import annotations

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import Rule


class DbtMissingRefRule(Rule):
    """
    Detects table references that do not use the dbt {{ ref('...') }} or {{ source('...') }} syntax.
    """
    id = "QUAL-DBT-001"
    name = "Missing dbt Ref"
    description = "Table references in dbt models should use {{ ref() }} or {{ source() }} instead of hardcoded names."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    def check(self, query: Query) -> list[Issue]:
        issues: list[Issue] = []
        if not query.ast:
            return issues

        for table in query.ast.find_all(exp.Table):
            table_name = table.name
            if not table_name:
                continue

            # If it's a Jinja dummy identifier created by our parser, it's fine.
            if "__jinja" in table_name.lower():
                continue

            # It's a hardcoded table name.
            issues.append(
                self.create_issue(
                    query=query,
                    message=f"Table '{table_name}' is hardcoded. Use {{{{ ref('{table_name}') }}}} or {{{{ source(...) }}}} instead.",
                    snippet=table.sql(),
                    location=query.location,
                )
            )
        return issues


class DbtHardcodedSchemaRule(Rule):
    """
    Detects hardcoded schema names in FROM/JOIN clauses in dbt models.
    """
    id = "QUAL-DBT-002"
    name = "Hardcoded Schema"
    description = "Avoid hardcoded schema names (e.g., myschema.mytable). Use dbt macros or source() instead."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    def check(self, query: Query) -> list[Issue]:
        issues: list[Issue] = []
        if not query.ast:
            return issues

        for table in query.ast.find_all(exp.Table):
            if table.db:
                schema_name = table.db
                # If schema is a jinja dummy, then it's fine
                if "__jinja" in schema_name.lower():
                    continue

                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Hardcoded schema '{schema_name}' found in table reference.",
                        snippet=table.sql(),
                        location=query.location,
                    )
                )
        return issues
