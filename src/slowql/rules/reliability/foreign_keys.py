"""
Reliability Foreign keys rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'CascadeDeleteRiskRule',
    'OrphanRecordRiskRule',
]


class OrphanRecordRiskRule(ASTRule):
    """Detects INSERT statements with potential orphan record risk."""

    id = "REL-FK-001"
    name = "Orphan Record Risk"
    description = (
        "Detects INSERT statements referencing likely foreign key columns without "
        "verifying parent record existence."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_FOREIGN_KEY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        # Common foreign key column patterns
        fk_patterns = {
            "user_id",
            "customer_id",
            "order_id",
            "product_id",
            "account_id",
            "parent_id",
            "category_id",
            "department_id",
            "company_id",
            "tenant_id",
            "created_by",
            "updated_by",
            "owner_id",
            "assigned_to",
            "manager_id",
        }

        for node in ast.walk():
            if isinstance(node, exp.Insert):
                # Get column list from INSERT
                columns = self._get_insert_columns(node)

                # Check if any FK-like columns are present
                fk_columns = set(c.lower() for c in columns) & fk_patterns

                if fk_columns:
                    # Check if query has subquery or JOIN verifying FK
                    query_upper = query.raw.upper()
                    has_fk_check = any(
                        term in query_upper
                        for term in ["FOREIGN KEY", "REFERENCES", "EXISTS", "JOIN"]
                    )

                    if not has_fk_check:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"INSERT with foreign key columns {fk_columns} without existence verification — orphan record risk.",
                                snippet=str(node)[:100],
                            )
                        )

        return issues

    def _get_insert_columns(self, node: Any) -> list[str]:
        columns = []
        if node.this and hasattr(node.this, "expressions"):
            for col in node.this.expressions:
                if hasattr(col, "name"):
                    columns.append(col.name)
        return columns

    impact = (
        "INSERTs without FK verification create orphan records when parent doesn't "
        "exist. If FK constraints are disabled or missing, data integrity is "
        "silently corrupted."
    )
    fix_guidance = (
        "Ensure FK constraints exist in schema. Or verify parent: INSERT INTO orders "
        "(user_id) SELECT ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ?). Use "
        "deferred FK checks if needed."
    )


class CascadeDeleteRiskRule(PatternRule):
    """Detects potential cascade delete risks on parent tables."""

    id = "REL-FK-002"
    name = "Cascade Delete Risk"
    description = (
        "Detects DELETE on parent tables that likely have cascading child records, "
        "risking unintended mass deletion."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_FOREIGN_KEY

    pattern = (
        r"\bDELETE\s+FROM\s+(users|customers|accounts|orders|products|categories|"
        r"departments|companies|tenants|organizations)\b(?!.*\bCASCADE\s*=\s*FALSE\b)"
    )
    message_template = "Potential mass delete on parent table: {match}"

    impact = (
        "DELETE on parent table with ON DELETE CASCADE can wipe millions of child "
        "records in one statement. Often unintended and irreversible without backups."
    )
    fix_guidance = (
        "Check child records before DELETE: SELECT COUNT(*) FROM child_table WHERE "
        "parent_id = ?. Use soft delete (is_deleted flag). Disable CASCADE for "
        "critical tables. Require explicit confirmation."
    )
