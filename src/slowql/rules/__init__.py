# slowql/src/slowql/rules/__init__.py
"""
Rules module for SlowQL.

This module provides:
- Base rule class for defining detection rules
- Rule registry for managing rules
- Rule catalog with all built-in rules

Rules are the atomic units of detection in SlowQL. Each rule
checks for a specific issue pattern and produces Issue objects
when the pattern is detected.

Example:
    >>> from slowql.rules import Rule, RuleRegistry
    >>>
    >>> class SelectStarRule(Rule):
    ...     id = "PERF-SCAN-001"
    ...     name = "SELECT * Usage"
    ...     dimension = Dimension.PERFORMANCE
    ...     severity = Severity.MEDIUM
    ...
    ...     def check(self, query):
    ...         # Detection logic...
    ...         pass
"""

from __future__ import annotations

# Import base classes first
from slowql.rules.base import (
    Rule,
    RuleMetadata,
    PatternRule,
    ASTRule,
    create_rule,
)

# Import registry components
from slowql.rules.registry import RuleRegistry, get_rule_registry

__all__ = [
    "Rule",
    "RuleMetadata",
    "PatternRule",
    "ASTRule",
    "RuleRegistry",
    "create_rule",
    "get_rule_registry",
]
