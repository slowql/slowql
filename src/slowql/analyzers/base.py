# slowql/src/slowql/analyzers/base.py
"""
Base analyzer class for SlowQL.

This module defines the abstract base class that all analyzers must
implement. Analyzers are responsible for examining parsed SQL queries
and detecting issues within their specific domain.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, ClassVar

from slowql.core.models import Dimension, Issue, Severity

if TYPE_CHECKING:
    from slowql.core.config import Config
    from slowql.core.models import Query
    from slowql.rules.base import Rule


@dataclass
class AnalyzerResult:
    """
    Result from running an analyzer on a query.

    Attributes:
        issues: List of detected issues.
        query: The analyzed query.
        analyzer_name: Name of the analyzer that produced this result.
        execution_time_ms: Time taken for analysis in milliseconds.
        rules_executed: Number of rules that were executed.
        rules_matched: Number of rules that found issues.
        metadata: Additional analyzer-specific metadata.
    """

    issues: list[Issue] = field(default_factory=list)
    query: Query | None = None
    analyzer_name: str = ""
    execution_time_ms: float = 0.0
    rules_executed: int = 0
    rules_matched: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Result is truthy if there are issues."""
        return len(self.issues) > 0

    def __len__(self) -> int:
        """Return number of issues."""
        return len(self.issues)

    def __iter__(self):
        """Iterate over issues."""
        return iter(self.issues)

    def add_issue(self, issue: Issue) -> None:
        """Add an issue to the result."""
        self.issues.append(issue)
        self.rules_matched += 1

    def filter_by_severity(self, min_severity: Severity) -> list[Issue]:
        """Get issues at or above a severity level."""
        return [i for i in self.issues if i.severity >= min_severity]


class BaseAnalyzer(ABC):
    """
    Abstract base class for all SQL analyzers.

    An analyzer is responsible for detecting issues within a specific
    dimension (security, performance, etc.). Each analyzer contains
    one or more rules that are applied to parsed queries.

    Subclasses must implement:
    - `dimension`: The dimension this analyzer covers
    - `analyze()`: The main analysis method

    Example:
        >>> class MySecurityAnalyzer(BaseAnalyzer):
        ...     name = "my-security"
        ...     dimension = Dimension.SECURITY
        ...     description = "Custom security checks"
        ...
        ...     def analyze(self, query, config=None):
        ...         issues = []
        ...         # Check for issues...
        ...         return issues

    Attributes:
        name: Unique identifier for the analyzer.
        dimension: The dimension this analyzer covers.
        description: Human-readable description.
        enabled: Whether the analyzer is enabled by default.
        priority: Execution priority (lower = earlier).
    """

    # Class attributes to be overridden by subclasses
    name: ClassVar[str] = "base"
    dimension: ClassVar[Dimension] = Dimension.QUALITY
    description: ClassVar[str] = "Base analyzer"
    enabled: ClassVar[bool] = True
    priority: ClassVar[int] = 100

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._rules: list[Rule] = []
        self._initialized = False

    def initialize(self) -> None:
        """
        Initialize the analyzer.

        Called once before first use. Subclasses can override to
        perform expensive initialization (loading patterns, etc.).
        """
        if not self._initialized:
            self._load_rules()
            self._initialized = True

    def _load_rules(self) -> None:
        """
        Load rules for this analyzer.

        Subclasses can override to load rules from various sources.
        The default implementation loads rules from the `get_rules()` method.
        """
        self._rules = list(self.get_rules())

    @property
    def rules(self) -> list[Rule]:
        """Get all rules for this analyzer."""
        if not self._initialized:
            self.initialize()
        return self._rules

    @abstractmethod
    def get_rules(self) -> list[Rule]:
        """
        Get the rules for this analyzer.

        Returns:
            List of Rule objects that this analyzer will apply.
        """
        ...

    @abstractmethod
    def analyze(
        self,
        query: Query,
        *,
        config: Config | None = None,
    ) -> list[Issue]:
        """
        Analyze a query for issues.

        Args:
            query: The parsed query to analyze.
            config: Optional configuration.

        Returns:
            List of detected issues.
        """
        ...

    def analyze_with_result(
        self,
        query: Query,
        *,
        config: Config | None = None,
    ) -> AnalyzerResult:
        """
        Analyze a query and return detailed result.

        Args:
            query: The parsed query to analyze.
            config: Optional configuration.

        Returns:
            AnalyzerResult with issues and metadata.
        """
        import time

        start_time = time.perf_counter()

        if not self._initialized:
            self.initialize()

        issues = self.analyze(query, config=config)

        execution_time = (time.perf_counter() - start_time) * 1000

        return AnalyzerResult(
            issues=issues,
            query=query,
            analyzer_name=self.name,
            execution_time_ms=execution_time,
            rules_executed=len(self._rules),
            rules_matched=len(set(i.rule_id for i in issues)),
        )

    def check_rule(
        self,
        query: Query,
        rule: Rule,
        *,
        config: Config | None = None,
    ) -> list[Issue]:
        """
        Check a single rule against a query.

        Args:
            query: The query to check.
            rule: The rule to apply.
            config: Optional configuration.

        Returns:
            List of issues found by this rule.
        """
        # Check if rule is disabled
        if config is not None:
            if rule.id in config.analysis.disabled_rules:
                return []
            if config.analysis.enabled_rules is not None:
                if rule.id not in config.analysis.enabled_rules:
                    # Also check prefix
                    prefix = "-".join(rule.id.split("-")[:2])
                    if prefix not in config.analysis.enabled_rules:
                        return []

        return rule.check(query)

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, "
            f"dimension={self.dimension.value!r}, "
            f"rules={len(self.rules)}"
            f")"
        )

    def __str__(self) -> str:
        """Return human-readable string."""
        return f"{self.name} ({self.dimension.value}): {self.description}"


class CompositeAnalyzer(BaseAnalyzer):
    """
    An analyzer that combines multiple sub-analyzers.

    This is useful for grouping related analyzers or creating
    custom analyzer combinations.

    Example:
        >>> composite = CompositeAnalyzer(
        ...     name="all-security",
        ...     analyzers=[InjectionAnalyzer(), AuthAnalyzer()],
        ... )
        >>> issues = composite.analyze(query)
    """

    def __init__(
        self,
        name: str,
        analyzers: list[BaseAnalyzer],
        *,
        dimension: Dimension = Dimension.QUALITY,
        description: str = "",
    ) -> None:
        """
        Initialize composite analyzer.

        Args:
            name: Name for the composite analyzer.
            analyzers: List of analyzers to combine.
            dimension: Primary dimension for the composite.
            description: Description of the composite analyzer.
        """
        super().__init__()
        self._name = name
        self._analyzers = analyzers
        self._dimension = dimension
        self._description = description or f"Composite of {len(analyzers)} analyzers"

    @property
    def name(self) -> str:  # type: ignore[override]
        return self._name

    @property
    def dimension(self) -> Dimension:  # type: ignore[override]
        return self._dimension

    @property
    def description(self) -> str:  # type: ignore[override]
        return self._description

    def get_rules(self) -> list[Rule]:
        """Get rules from all sub-analyzers."""
        rules = []
        for analyzer in self._analyzers:
            rules.extend(analyzer.rules)
        return rules

    def analyze(
        self,
        query: Query,
        *,
        config: Config | None = None,
    ) -> list[Issue]:
        """Run all sub-analyzers."""
        issues = []
        for analyzer in self._analyzers:
            issues.extend(analyzer.analyze(query, config=config))
        return issues


class RuleBasedAnalyzer(BaseAnalyzer):
    """
    An analyzer that applies a collection of rules.

    This is the most common analyzer pattern. Subclasses define
    rules in `get_rules()`, and the base `analyze()` method
    applies each rule to the query.

    Example:
        >>> class PerformanceAnalyzer(RuleBasedAnalyzer):
        ...     name = "performance"
        ...     dimension = Dimension.PERFORMANCE
        ...
        ...     def get_rules(self):
        ...         return [
        ...             SelectStarRule(),
        ...             MissingWhereRule(),
        ...             # ...
        ...         ]
    """

    def analyze(
        self,
        query: Query,
        *,
        config: Config | None = None,
    ) -> list[Issue]:
        """
        Apply all rules to the query.

        Args:
            query: The query to analyze.
            config: Optional configuration.

        Returns:
            List of all issues found.
        """
        if not self._initialized:
            self.initialize()

        issues: list[Issue] = []

        for rule in self._rules:
            try:
                rule_issues = self.check_rule(query, rule, config=config)
                issues.extend(rule_issues)
            except Exception as e:
                # Log but don't fail on individual rule errors
                # In production, this would log to proper logging
                import sys
                print(
                    f"Warning: Rule {rule.id} failed on query: {e}",
                    file=sys.stderr,
                )

        return issues

    def get_rules(self) -> list[Rule]:
        """
        Get rules for this analyzer.

        Must be implemented by subclasses.

        Returns:
            List of rules to apply.
        """
        return []


class PatternAnalyzer(RuleBasedAnalyzer):
    """
    An analyzer that uses regex patterns to detect issues.

    This is useful for simple pattern-based detection where
    full AST analysis is not needed.

    Example:
        >>> class SimpleSecurityAnalyzer(PatternAnalyzer):
        ...     name = "simple-security"
        ...     dimension = Dimension.SECURITY
        ...     patterns = [
        ...         (r"password\s*=\s*'[^']+'", "SEC-001", "Hardcoded password"),
        ...     ]
    """

    # List of (pattern, rule_id, message) tuples
    patterns: ClassVar[list[tuple[str, str, str, Severity]]] = []

    def __init__(self) -> None:
        """Initialize and compile patterns."""
        super().__init__()
        self._compiled_patterns: list[tuple[Any, str, str, Severity]] = []

    def initialize(self) -> None:
        """Compile regex patterns."""
        import re

        super().initialize()

        for pattern, rule_id, message, severity in self.patterns:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._compiled_patterns.append((compiled, rule_id, message, severity))

    def analyze(
        self,
        query: Query,
        *,
        config: Config | None = None,
    ) -> list[Issue]:
        """Apply pattern matching to the query."""
        if not self._initialized:
            self.initialize()

        issues: list[Issue] = []
        sql = query.raw

        for pattern, rule_id, message, severity in self._compiled_patterns:
            # Check if rule is disabled
            if config is not None:
                if rule_id in config.analysis.disabled_rules:
                    continue

            match = pattern.search(sql)
            if match:
                issue = Issue(
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    dimension=self.dimension,
                    location=query.location,
                    snippet=match.group(0),
                )
                issues.append(issue)

        return issues

    def get_rules(self) -> list[Rule]:
        """Pattern analyzers don't use Rule objects."""
        return []


# Type alias for analyzer factory functions
AnalyzerFactory = Callable[[], BaseAnalyzer]
