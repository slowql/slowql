from __future__ import annotations

"""
Quality Naming rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'AmbiguousAliasRule',
    'HungarianNotationRule',
    'InconsistentTableNamingRule',
    'ReservedWordAsColumnRule',
]


class InconsistentTableNamingRule(ASTRule):
    """Detects inconsistent table naming (e.g., Mixing plural and singular)."""

    id = "QUAL-NAME-001"
    name = "Inconsistent Table Naming"
    description = (
        "Detects inconsistent table naming conventions, specifically mixing singular and "
        "plural names in the same query."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_NAMING

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        tables = [t.name.lower() for t in ast.find_all(exp.Table) if t.name]

        if len(tables) < 2:
            return []

        # Standardize: plural usually ends with 's', but not 'ss' (like 'process')
        # This is a heuristic for detecting mixtures.
        likely_singular = [t for t in tables if not t.endswith('s') or t.endswith('ss')]
        likely_plural = [t for t in tables if t.endswith('s') and not t.endswith('ss')]

        # Only flag if we have a clear mixture of both patterns
        if likely_singular and likely_plural:
            # Check if they are actually different words (not just 'user' and 'user')
            issues.append(
                self.create_issue(
                    query=query,
                    message=f"Inconsistent table naming detected: mixed singular ({likely_singular[0]}) and plural ({likely_plural[0]}) names",
                    snippet=", ".join(tables[:5]),
                )
            )

        return issues

    impact = (
        "Inconsistent naming makes the schema harder to learn and navigate. It creates "
        "uncertainty for developers and often leads to bugs where the wrong table name is guessed."
    )
    fix_guidance = (
        "Standardize on either singular (user) or plural (users) for all table names. "
        "Plural is common for collections, singular for entity definitions."
    )


class AmbiguousAliasRule(ASTRule):
    """Detects overly short or ambiguous aliases (e.g., a, b, t1)."""

    id = "QUAL-NAME-002"
    name = "Ambiguous Alias"
    description = "Detects overly short (1-2 chars) or generic aliases that hinder readability."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_NAMING

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            alias = None
            if isinstance(node, (exp.Alias, exp.Table)):
                alias = getattr(node, 'alias', None)

            if alias and len(alias) <= 2 and alias.lower() not in ('as', 'id'):
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Ambiguous alias '{alias}' detected - use descriptive names (e.g., 'usr' instead of 'u')",
                        snippet=str(node)[:50],
                    )
                )

        return issues

    impact = (
        "Single-letter aliases make complex queries impossible to read without constant "
        "referencing back to the source. They hide the semantic meaning of the data."
    )
    fix_guidance = (
        "Use 3+ character descriptive aliases. Example: 'cust' for customers, 'emp' for employees. "
        "Avoid aliases like 'a', 'b', 't1'."
    )


class HungarianNotationRule(PatternRule):
    """Detects Hungarian notation in column/table names (e.g., strName, intId)."""

    id = "QUAL-NAME-003"
    name = "Hungarian Notation in Names"
    description = "Detects Hungarian notation prefixing (e.g., str_name, i_id, tbl_users)."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_NAMING

    pattern = r'\b(str_|int_|i_|tbl_|v_|idx_|fk_|pk_)[a-z0-9_]+\b'

    impact = (
        "Hungarian notation is redundant in SQL as types are defined in schema. It makes "
        "renaming/typing changes harder and clutters the code with obsolete metaphors."
    )
    fix_guidance = (
        "Remove type prefixes. Use 'name' instead of 'str_name', 'id' instead of 'int_id'. "
        "Database metadata already provides type information."
    )


class ReservedWordAsColumnRule(ASTRule):
    """Detects use of SQL reserved words as column or table names."""

    id = "QUAL-NAME-004"
    name = "Reserved Word as Identifier"
    description = "Detects use of SQL reserved words (ORDER, GROUP, TABLE, etc.) as identifiers."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_NAMING

    RESERVED = {
        'ORDER', 'GROUP', 'BY', 'SELECT', 'FROM', 'WHERE', 'TABLE', 'INDEX',
        'USER', 'DATE', 'KEY', 'COLUMN', 'AS', 'JOIN', 'LIMIT', 'OFFSET'
    }

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        # Check all identifiers, including those sqlglot might identify as words
        for node in ast.walk():
            name = None
            if isinstance(node, (exp.Column, exp.Table, exp.Identifier)):
                if isinstance(node, exp.Identifier):
                    name = node.this
                else:
                    name = node.alias_or_name

            if name and isinstance(name, str) and name.upper() in self.RESERVED:
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Reserved word '{name.upper()}' used as identifier",
                        snippet=str(node),
                    )
                )

        return issues

    impact = (
        "Using reserved words forces the use of double quotes and can lead to syntax errors "
        "if quotes are missing. It also makes queries much harder to read."
    )
    fix_guidance = (
        "Choose a non-reserved synonym. Use 'created_at' instead of 'DATE', "
        "'sort_order' instead of 'ORDER', 'user_account' instead of 'USER'."
    )
