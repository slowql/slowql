"""
Quality Schema design rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'LackOfIndexingOnForeignKeyRule',
    'MissingForeignKeyRule',
    'MissingPrimaryKeyRule',
    'UsingFloatForCurrencyRule',
]


class MissingPrimaryKeyRule(PatternRule):
    """Detects CREATE TABLE without PRIMARY KEY."""

    id = "QUAL-SCHEMA-001"
    name = "Missing Primary Key"
    description = "Detects table definitions missing a PRIMARY KEY constraint."
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_SCHEMA_DESIGN

    pattern = r'CREATE\s+TABLE\s+(?:(?!PRIMARY\s+KEY).)*?(?:\);|\Z)'

    impact = (
        "Tables without primary keys are a major design flaw. They prevent row uniqueness, "
        "break replication, make updates slow, and hinder most database optimizations."
    )
    fix_guidance = (
        "Add a PRIMARY KEY to the table. Usually an auto-incrementing ID or a UUID. "
        "Every table must have a unique identifier."
    )


class MissingForeignKeyRule(ASTRule):
    """Detects columns named like *_id without FOREIGN KEY constraints."""

    id = "QUAL-SCHEMA-002"
    name = "Implicit Foreign Key (Logic)"
    description = "Detects columns following *_id pattern missing explicit FOREIGN KEY constraints."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_SCHEMA_DESIGN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        if not isinstance(ast, exp.Create):
            return []

        table_def = ast.this
        if not isinstance(table_def, exp.Schema):
            return []

        columns = [c.this.name.lower() for c in table_def.find_all(exp.ColumnDef)]
        fks = []
        for f in table_def.find_all(exp.ForeignKey):
            col_node = f.find(exp.Column)
            if col_node:
                fks.append(col_node.name.lower())
            else:
                # If sqlglot doesn't provide Column child, try to find Identifier
                id_node = f.find(exp.Identifier)
                if id_node:
                    fks.append(id_node.this.lower())

        for col in columns:
            if col.endswith('_id') and col != 'id' and col not in fks:
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Column '{col}' looks like a foreign key but lacks a constraint",
                        snippet=col,
                    )
                )

        return issues

    impact = (
        "Missing foreign keys lead to orphaned records and data corruption. Referenced data "
        "can be deleted without cleaning up dependent rows, breaking application logic."
    )
    fix_guidance = (
        "Add FOREIGN KEY ... REFERENCES ... constraints. This ensures referential integrity "
        "at the database level."
    )


class LackOfIndexingOnForeignKeyRule(ASTRule):
    """Detects foreign keys without supporting indexes."""

    id = "QUAL-SCHEMA-003"
    name = "Missing Index on Foreign Key"
    description = "Detects foreign key columns that lack a corresponding INDEX."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_SCHEMA_DESIGN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        if not isinstance(ast, exp.Create):
            return []

        table_def = ast.this
        if not isinstance(table_def, exp.Schema):
            return []

        # Get all indexes/keys
        indexed_cols = set()
        for idx in table_def.find_all((exp.Index, exp.IndexColumnConstraint)):  # type: ignore[var-annotated,arg-type]
            for ident in idx.find_all(exp.Identifier):
                indexed_cols.add(ident.this.lower())

        for fk in table_def.find_all(exp.ForeignKey):
            # expressions contains the local columns (Identifiers)
            local_idents = fk.expressions
            local_names = {ident.this.lower() for ident in local_idents if isinstance(ident, exp.Identifier)}

            for col_name in local_names:
                if col_name not in indexed_cols:
                    issues.append(
                        self.create_issue(query=query, message=f"Missing index on FK '{col_name}'", snippet=str(fk))
                    )

        return issues

    impact = (
        "JOINs and CASCADE deletes on unindexed foreign keys are extremely slow. They cause "
        "full table scans for every referenced record lookup, killing performance."
    )
    fix_guidance = (
        "Create an INDEX on the foreign key column. Most databases do not index "
        "FKs automatically. Example: CREATE INDEX idx_users_id ON profiles(user_id)."
    )


class UsingFloatForCurrencyRule(PatternRule):
    """Detects FLOAT/REAL types for currency (e.g., price FLOAT)."""

    id = "QUAL-SCHEMA-004"
    name = "Float for Currency"
    description = "Detects use of approximate types (FLOAT, REAL) for monetary values."
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_SCHEMA_DESIGN

    pattern = r'\b(price|amount|balance|cost|total|sum)\b.*?\b(FLOAT|REAL|DOUBLE)\b'

    impact = (
        "Float/Double types use binary floating-point math which leads to rounding errors (e.g., "
        "0.1 + 0.2 != 0.3). This is catastrophic for financial data."
    )
    fix_guidance = (
        "Use DECIMAL or NUMERIC for currency. Or store as integer (cents/pence). "
        "Never use floating point types for money."
    )
