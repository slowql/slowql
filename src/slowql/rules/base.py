# slowql/src/slowql/rules/base.py
"""
Base rule class for SlowQL.

This module defines the Rule base class and supporting utilities
for creating SQL detection rules.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from re import Pattern
from typing import TYPE_CHECKING, Any, ClassVar

from sqlglot import exp

from slowql.core.models import (
    Category,
    Dimension,
    Fix,
    Issue,
    Location,
    Severity,
)
from slowql.rules.registry import RuleRegistry, get_rule_registry

if TYPE_CHECKING:
    from collections.abc import Callable

    from slowql.core.models import Query


@dataclass(frozen=True)
class RuleMetadata:
    """
    Metadata about a rule.

    This provides descriptive information about a rule for
    documentation and UI display.

    Attributes:
        id: Unique rule identifier (e.g., "SEC-INJ-001").
        name: Human-readable rule name.
        description: Detailed description of what the rule detects.
        severity: Default severity level.
        dimension: The dimension this rule belongs to.
        category: Optional sub-category within the dimension.
        impact: Description of the potential impact.
        rationale: Why this issue matters.
        examples: Example queries that trigger this rule.
        references: Links to external documentation.
        tags: Additional tags for filtering.
        fix_guidance: General guidance on fixing the issue.
    """

    id: str
    name: str
    description: str
    severity: Severity
    dimension: Dimension
    category: Category | None = None
    impact: str = ""
    rationale: str = ""
    examples: tuple[str, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    fix_guidance: str = ""

    @property
    def documentation_url(self) -> str:
        """Get URL to documentation for this rule."""
        return f"https://slowql.dev/rules/{self.id.lower()}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "dimension": self.dimension.value,
            "category": self.category.value if self.category else None,
            "impact": self.impact,
            "rationale": self.rationale,
            "examples": list(self.examples),
            "references": list(self.references),
            "tags": list(self.tags),
            "fix_guidance": self.fix_guidance,
            "documentation_url": self.documentation_url,
        }


class Rule(ABC):
    """
    Abstract base class for detection rules.

    Each rule detects a specific issue pattern in SQL queries.
    Rules are typically organized by dimension and category.

    Subclasses must implement:
    - `id`: Unique rule identifier
    - `check()`: The detection logic

    Class Attributes:
        id: Unique rule identifier (e.g., "PERF-IDX-001").
        name: Human-readable rule name.
        description: What this rule detects.
        severity: Severity level of issues.
        dimension: The dimension (security, performance, etc.).
        category: Optional sub-category.
        enabled: Whether rule is enabled by default.
        tags: Additional tags for filtering.

    Example:
        >>> class SelectStarRule(Rule):
        ...     id = "PERF-SCAN-001"
        ...     name = "SELECT * Usage"
        ...     description = "Detects SELECT * which can cause performance issues"
        ...     severity = Severity.MEDIUM
        ...     dimension = Dimension.PERFORMANCE
        ...
        ...     def check(self, query):
        ...         if query.query_type == "SELECT" and "*" in query.raw:
        ...             return [self.create_issue(
        ...                 query=query,
        ...                 message="Avoid SELECT *, specify columns explicitly",
        ...                 snippet="SELECT *",
        ...             )]
        ...         return []
    """

    # Class attributes - override in subclasses
    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    dimension: ClassVar[Dimension] = Dimension.QUALITY
    category: ClassVar[Category | None] = None
    enabled: ClassVar[bool] = True
    tags: ClassVar[tuple[str, ...]] = ()

    # Optional attributes
    impact: ClassVar[str] = ""
    rationale: ClassVar[str] = ""
    fix_guidance: ClassVar[str] = ""
    examples: ClassVar[tuple[str, ...]] = ()
    references: ClassVar[tuple[str, ...]] = ()

    def __init__(self) -> None:
        """Initialize the rule."""
        self._compiled_patterns: dict[str, Pattern[str]] = {}

    @abstractmethod
    def check(self, query: Query) -> list[Issue]:
        """
        Check a query for this rule's issue pattern.

        Args:
            query: The parsed query to check.

        Returns:
            List of Issue objects for each detected occurrence.
        """
        ...

    @property
    def metadata(self) -> RuleMetadata:
        """Get rule metadata."""
        return RuleMetadata(
            id=self.id,
            name=self.name,
            description=self.description,
            severity=self.severity,
            dimension=self.dimension,
            category=self.category,
            impact=self.impact,
            rationale=self.rationale,
            examples=self.examples,
            references=self.references,
            tags=self.tags,
            fix_guidance=self.fix_guidance,
        )

    def create_issue(
        self,
        query: Query,
        message: str,
        snippet: str,
        *,
        severity: Severity | None = None,
        location: Location | None = None,
        fix: Fix | None = None,
        impact: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Issue:
        """
        Create an issue for this rule.

        This is a helper method that pre-fills common issue fields
        from the rule's class attributes.

        Args:
            query: The query where the issue was found.
            message: The issue message.
            snippet: The problematic code snippet.
            severity: Override severity (uses rule default if None).
            location: Override location (uses query location if None).
            fix: Optional suggested fix.
            impact: Override impact description.
            metadata: Additional metadata.

        Returns:
            A new Issue object.
        """
        return Issue(
            rule_id=self.id,
            message=message,
            severity=severity or self.severity,
            dimension=self.dimension,
            category=self.category,
            location=location or query.location,
            snippet=snippet,
            fix=fix,
            impact=impact or self.impact,
            documentation_url=self.metadata.documentation_url,
            tags=self.tags,
            metadata=metadata or {},
        )

    def _compile_pattern(self, pattern: str, flags: int = re.IGNORECASE) -> Pattern[str]:
        """
        Compile and cache a regex pattern.

        Args:
            pattern: The regex pattern string.
            flags: Regex flags.

        Returns:
            Compiled pattern.
        """
        cache_key = f"{pattern}:{flags}"
        if cache_key not in self._compiled_patterns:
            self._compiled_patterns[cache_key] = re.compile(pattern, flags)
        return self._compiled_patterns[cache_key]

    def _find_pattern(
        self,
        sql: str,
        pattern: str,
        flags: int = re.IGNORECASE,
    ) -> list[re.Match[str]]:
        """
        Find all matches of a pattern in SQL.

        Args:
            sql: The SQL string to search.
            pattern: The regex pattern.
            flags: Regex flags.

        Returns:
            List of match objects.
        """
        compiled = self._compile_pattern(pattern, flags)
        return list(compiled.finditer(sql))

    def _has_pattern(
        self,
        sql: str,
        pattern: str,
        flags: int = re.IGNORECASE,
    ) -> bool:
        """
        Check if SQL contains a pattern.

        Args:
            sql: The SQL string to search.
            pattern: The regex pattern.
            flags: Regex flags.

        Returns:
            True if pattern is found.
        """
        compiled = self._compile_pattern(pattern, flags)
        return compiled.search(sql) is not None

    def __repr__(self) -> str:
        """Return string representation."""
        return f"{self.__class__.__name__}(id={self.id!r})"

    def __str__(self) -> str:
        """Return human-readable string."""
        return f"[{self.id}] {self.name}"


class PatternRule(Rule):
    r"""
    A rule that uses regex pattern matching.

    This is a convenience base class for simple pattern-based rules.
    Subclasses only need to define the pattern and message.

    Class Attributes:
        pattern: The regex pattern to match.
        message_template: Message template (can use {match} placeholder).

    Example:
        >>> class PasswordInQueryRule(PatternRule):
        ...     id = "SEC-AUTH-001"
        ...     name = "Hardcoded Password"
        ...     pattern = r"password\s*=\s*'[^']+'"
        ...     message_template = "Hardcoded password detected: {match}"
        ...     severity = Severity.CRITICAL
        ...     dimension = Dimension.SECURITY
    """

    pattern: ClassVar[str] = ""
    message_template: ClassVar[str] = "Pattern matched: {match}"
    pattern_flags: ClassVar[int] = re.IGNORECASE

    def check(self, query: Query) -> list[Issue]:
        """Check query against the pattern."""
        if not self.pattern:
            return []

        issues = []
        matches = self._find_pattern(query.raw, self.pattern, self.pattern_flags)

        for match in matches:
            message = self.message_template.format(
                match=match.group(0),
                **match.groupdict(),
            )
            issues.append(
                self.create_issue(
                    query=query,
                    message=message,
                    snippet=match.group(0),
                )
            )

        return issues


class ASTRule(Rule):
    """
    A rule that operates on the AST.

    This base class provides utilities for rules that need to
    analyze the parsed AST structure rather than raw SQL text.

    Subclasses implement `check_ast()` instead of `check()`.

    Example:
        >>> class NoWhereDeleteRule(ASTRule):
        ...     id = "REL-DATA-001"
        ...     name = "DELETE without WHERE"
        ...     severity = Severity.CRITICAL
        ...     dimension = Dimension.RELIABILITY
        ...
        ...     def check_ast(self, query, ast):
        ...         if query.query_type == "DELETE":
        ...             if not self._has_where_clause(ast):
        ...                 return [self.create_issue(...)]
        ...         return []
    """

    def check(self, query: Query) -> list[Issue]:
        """Check query by analyzing AST."""
        if query.ast is None:
            return []
        return self.check_ast(query, query.ast)

    @abstractmethod
    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        """
        Check the query AST for issues.

        Args:
            query: The parsed query.
            ast: The sqlglot AST node.

        Returns:
            List of detected issues.
        """
        ...

    def _has_where_clause(self, ast: Any) -> bool:
        """Check if AST has a WHERE clause."""
        return ast.find(exp.Where) is not None

    def _get_tables(self, ast: Any) -> list[str]:
        """Get table names from AST."""
        tables = []
        for table in ast.find_all(exp.Table):
            tables.append(table.name)
        return tables

    def _get_columns(self, ast: Any) -> list[str]:
        """Get column names from AST."""
        columns = []
        for col in ast.find_all(exp.Column):
            columns.append(col.name)
        return columns

    def _get_functions(self, ast: Any) -> list[str]:
        """Get function names from AST."""
        functions = []
        for func in ast.find_all(exp.Func):
            functions.append(func.name if hasattr(func, "name") else func.__class__.__name__)
        return functions


# Factory function for creating simple rules
def create_rule(
    id: str,
    name: str,
    description: str,
    severity: Severity,
    dimension: Dimension,
    check_fn: Callable[[Query], list[Issue]],
    *,
    category: Category | None = None,
    enabled: bool = True,
    tags: tuple[str, ...] = (),
    impact: str = "",
    fix_guidance: str = "",
) -> Rule:
    """
    Factory function to create a rule from a check function.

    This is useful for creating simple rules without defining a class.

    Args:
        id: Rule ID.
        name: Rule name.
        description: Rule description.
        severity: Severity level.
        dimension: Dimension.
        check_fn: Function that takes a Query and returns Issues.
        category: Optional category.
        enabled: Whether enabled by default.
        tags: Additional tags.
        impact: Impact description.
        fix_guidance: Fix guidance.

    Returns:
        A Rule instance.

    Example:
        >>> rule = create_rule(
        ...     id="CUSTOM-001",
        ...     name="Custom Check",
        ...     description="A custom check",
        ...     severity=Severity.LOW,
        ...     dimension=Dimension.QUALITY,
        ...     check_fn=lambda q: [] if "ok" in q.raw else [Issue(...)],
        ... )
    """

    class DynamicRule(Rule):
        def check(self, query: Query) -> list[Issue]:
            return check_fn(query)

    # Set class attributes
    DynamicRule.id = id
    DynamicRule.name = name
    DynamicRule.description = description
    DynamicRule.severity = severity
    DynamicRule.dimension = dimension
    DynamicRule.category = category
    DynamicRule.enabled = enabled
    DynamicRule.tags = tags
    DynamicRule.impact = impact
    DynamicRule.fix_guidance = fix_guidance

    # Instantiate
    return DynamicRule()


__all__ = [
    "ASTRule",
    "PatternRule",
    "Rule",
    "RuleMetadata",
    "RuleRegistry",
    "create_rule",
    "get_rule_registry",
]
