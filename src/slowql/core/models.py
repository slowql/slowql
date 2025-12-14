# slowql/src/slowql/core/models.py
"""
Core data models for SlowQL.

This module defines the fundamental data structures used throughout SlowQL:
- Severity levels for issues
- Issue dimensions (security, performance, etc.)
- Location tracking for source mapping
- Issue representation
- Analysis results
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any


class Severity(str, Enum):
    """
    Severity levels for detected issues.

    Severity determines how critical an issue is and how urgently
    it should be addressed.

    Attributes:
        CRITICAL: Must fix immediately. Data loss, security breach risk.
        HIGH: Should fix before production. Significant impact.
        MEDIUM: Should fix soon. Moderate impact.
        LOW: Nice to fix. Minor impact or code quality.
        INFO: Informational. Suggestions and best practices.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def emoji(self) -> str:
        """Return emoji representation for CLI display."""
        return {
            Severity.CRITICAL: "💀",
            Severity.HIGH: "🔥",
            Severity.MEDIUM: "⚡",
            Severity.LOW: "💫",
            Severity.INFO: "💡",
        }[self]

    @property
    def color(self) -> str:
        """Return Rich color for CLI display."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]

    @property
    def weight(self) -> int:
        """Return numeric weight for sorting (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    def __lt__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight < other.weight

    def __le__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight <= other.weight

    def __gt__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight > other.weight

    def __ge__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight >= other.weight


class Dimension(str, Enum):
    """
    Analysis dimensions categorizing types of issues.

    Each dimension represents a major area of concern in SQL analysis.
    Issues are categorized by dimension to help prioritize fixes
    based on organizational priorities.
    """

    SECURITY = "security"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    COMPLIANCE = "compliance"
    COST = "cost"
    QUALITY = "quality"
    SCHEMA = "schema"
    DATA = "data"
    MIGRATION = "migration"
    OPERATIONAL = "operational"
    BUSINESS = "business"

    @property
    def emoji(self) -> str:
        """Return emoji representation for CLI display."""
        return {
            Dimension.SECURITY: "🔒",
            Dimension.PERFORMANCE: "⚡",
            Dimension.RELIABILITY: "🛡️",
            Dimension.COMPLIANCE: "📋",
            Dimension.COST: "💰",
            Dimension.QUALITY: "📝",
            Dimension.SCHEMA: "🏛️",
            Dimension.DATA: "📊",
            Dimension.MIGRATION: "🔄",
            Dimension.OPERATIONAL: "⚙️",
            Dimension.BUSINESS: "🧠",
        }[self]

    @property
    def color(self) -> str:
        """Return Rich color for CLI display."""
        return {
            Dimension.SECURITY: "red",
            Dimension.PERFORMANCE: "yellow",
            Dimension.RELIABILITY: "blue",
            Dimension.COMPLIANCE: "magenta",
            Dimension.COST: "green",
            Dimension.QUALITY: "cyan",
            Dimension.SCHEMA: "white",
            Dimension.DATA: "bright_blue",
            Dimension.MIGRATION: "bright_yellow",
            Dimension.OPERATIONAL: "bright_magenta",
            Dimension.BUSINESS: "bright_cyan",
        }[self]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return {
            Dimension.SECURITY: "Security vulnerabilities and risks",
            Dimension.PERFORMANCE: "Performance anti-patterns and optimizations",
            Dimension.RELIABILITY: "Data integrity and reliability issues",
            Dimension.COMPLIANCE: "Regulatory compliance concerns",
            Dimension.COST: "Cost optimization opportunities",
            Dimension.QUALITY: "Code quality and maintainability",
            Dimension.SCHEMA: "Schema design issues",
            Dimension.DATA: "Data quality and patterns",
            Dimension.MIGRATION: "Migration and compatibility",
            Dimension.OPERATIONAL: "Operational concerns",
            Dimension.BUSINESS: "Business logic issues",
        }[self]


class Category(str, Enum):
    """
    Detailed categories within dimensions.

    Categories provide finer-grained classification of issues
    within each dimension.
    """

    # Security categories
    SEC_INJECTION = "injection"
    SEC_AUTHENTICATION = "authentication"
    SEC_DATA_EXPOSURE = "data-exposure"
    SEC_CRYPTO = "cryptography"
    SEC_ACCESS = "access-control"

    # Performance categories
    PERF_INDEX = "index"
    PERF_SCAN = "table-scan"
    PERF_JOIN = "join"
    PERF_SUBQUERY = "subquery"
    PERF_AGGREGATION = "aggregation"
    PERF_SORT = "sorting"
    PERF_LOCK = "locking"
    PERF_MEMORY = "memory"

    # Reliability categories
    REL_DATA_INTEGRITY = "data-integrity"
    REL_TRANSACTION = "transaction"
    REL_ERROR_HANDLING = "error-handling"
    REL_RECOVERY = "recovery"

    # Compliance categories
    COMP_GDPR = "gdpr"
    COMP_HIPAA = "hipaa"
    COMP_PCI = "pci-dss"
    COMP_SOX = "sox"
    COMP_SOC2 = "soc2"

    # Cost categories
    COST_CLOUD = "cloud"
    COST_STORAGE = "storage"
    COST_COMPUTE = "compute"

    # Quality categories
    QUAL_READABILITY = "readability"
    QUAL_NAMING = "naming"
    QUAL_DRY = "dry"
    QUAL_MODERN = "modern-sql"


@dataclass(frozen=True, slots=True)
class Location:
    """
    Source location for an issue.

    Tracks where in the source code an issue was detected,
    enabling precise error reporting and IDE integration.

    Attributes:
        line: 1-indexed line number.
        column: 1-indexed column number.
        end_line: Optional end line for multi-line issues.
        end_column: Optional end column.
        file: Optional file path.
        query_index: Index of query in file (for multi-query files).
    """

    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None
    file: str | None = None
    query_index: int | None = None

    def __str__(self) -> str:
        """Return human-readable location string."""
        parts = []
        if self.file:
            parts.append(self.file)
        parts.append(f"{self.line}:{self.column}")
        if self.end_line and self.end_column:
            parts.append(f"-{self.end_line}:{self.end_column}")
        return ":".join(parts) if self.file else "".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "file": self.file,
            "query_index": self.query_index,
        }


@dataclass(frozen=True, slots=True)
class Fix:
    """
    Suggested fix for an issue.

    Contains the replacement code and description of the fix.
    Can be applied automatically or used as guidance.

    Attributes:
        description: Human-readable description of the fix.
        replacement: The SQL code to replace the problematic code.
        is_safe: Whether the fix can be safely auto-applied.
        confidence: Confidence level (0.0 to 1.0) in the fix.
    """

    description: str
    replacement: str
    is_safe: bool = False
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "description": self.description,
            "replacement": self.replacement,
            "is_safe": self.is_safe,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class Issue:
    """
    A detected issue in SQL code.

    This is the primary output of SlowQL analysis. Each issue
    represents a single problem or improvement opportunity
    found in the analyzed SQL.

    Attributes:
        rule_id: Unique identifier for the rule (e.g., "SEC-INJ-001").
        message: Human-readable description of the issue.
        severity: How critical the issue is.
        dimension: Category of the issue (security, performance, etc.).
        location: Where in the source the issue was found.
        snippet: The problematic SQL code snippet.
        fix: Optional suggested fix.
        impact: Description of potential impact if not fixed.
        documentation_url: URL to detailed documentation.
        tags: Additional tags for filtering.
        metadata: Additional context-specific data.
    """

    rule_id: str
    message: str
    severity: Severity
    dimension: Dimension
    location: Location
    snippet: str
    fix: Fix | None = None
    impact: str | None = None
    documentation_url: str | None = None
    category: Category | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate issue data."""
        if not self.rule_id:
            raise ValueError("rule_id is required")
        if not self.message:
            raise ValueError("message is required")

    @property
    def code(self) -> str:
        """Alias for rule_id for compatibility."""
        return self.rule_id

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "dimension": self.dimension.value,
            "category": self.category.value if self.category else None,
            "location": self.location.to_dict(),
            "snippet": self.snippet,
            "fix": self.fix.to_dict() if self.fix else None,
            "impact": self.impact,
            "documentation_url": self.documentation_url,
            "tags": list(self.tags),
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class Query:
    """
    Represents a parsed SQL query with metadata.

    Attributes:
        raw: The original SQL string.
        normalized: Normalized/formatted SQL.
        dialect: Detected or specified SQL dialect.
        location: Starting location in source.
        ast: Parsed AST (dialect-specific).
        tables: Tables referenced in the query.
        columns: Columns referenced in the query.
        query_type: Type of query (SELECT, INSERT, etc.).
    """

    raw: str
    normalized: str
    dialect: str
    location: Location
    ast: Any = None
    tables: tuple[str, ...] = field(default_factory=tuple)
    columns: tuple[str, ...] = field(default_factory=tuple)
    query_type: str | None = None

    @property
    def is_select(self) -> bool:
        """Check if query is a SELECT statement."""
        return self._check_type("SELECT")

    @property
    def is_insert(self) -> bool:
        """Check if query is an INSERT statement."""
        return self._check_type("INSERT")

    @property
    def is_update(self) -> bool:
        """Check if query is an UPDATE statement."""
        return self._check_type("UPDATE")

    @property
    def is_delete(self) -> bool:
        """Check if query is a DELETE statement."""
        return self._check_type("DELETE")
        
    def _check_type(self, type_name: str) -> bool:
        """Helper to check query type safely."""
        return str(self.query_type or "").upper() == type_name

    def __hash__(self) -> int:
        """Hash based on normalized SQL."""
        return hash(self.normalized)


@dataclass(slots=True)
class Statistics:
    """
    Statistics about an analysis run.

    Attributes:
        total_queries: Number of queries analyzed.
        total_issues: Total number of issues found.
        by_severity: Issue counts by severity level.
        by_dimension: Issue counts by dimension.
        analysis_time_ms: Time taken for analysis in milliseconds.
        parse_time_ms: Time taken for parsing in milliseconds.
    """

    total_queries: int = 0
    total_issues: int = 0
    by_severity: dict[Severity, int] = field(default_factory=dict)
    by_dimension: dict[Dimension, int] = field(default_factory=dict)
    analysis_time_ms: float = 0.0
    parse_time_ms: float = 0.0

    def __post_init__(self) -> None:
        """Initialize severity and dimension counts."""
        if not self.by_severity:
            self.by_severity = {s: 0 for s in Severity}
        if not self.by_dimension:
            self.by_dimension = {d: 0 for d in Dimension}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "total_queries": self.total_queries,
            "total_issues": self.total_issues,
            "by_severity": {k.value: v for k, v in self.by_severity.items()},
            "by_dimension": {k.value: v for k, v in self.by_dimension.items()},
            "analysis_time_ms": self.analysis_time_ms,
            "parse_time_ms": self.parse_time_ms,
        }


@dataclass(slots=True)
class AnalysisResult:
    """
    Complete result of an analysis run.

    This is the top-level output from SlowQL analysis, containing
    all detected issues, statistics, and metadata.

    Attributes:
        issues: List of all detected issues.
        statistics: Aggregate statistics.
        dialect: SQL dialect used for analysis.
        queries: List of parsed queries.
        timestamp: When the analysis was performed.
        version: SlowQL version used.
        config_hash: Hash of configuration for reproducibility.
    """

    issues: list[Issue] = field(default_factory=list)
    statistics: Statistics = field(default_factory=Statistics)
    dialect: str | None = None
    queries: list[Query] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "2.0.0"
    config_hash: str | None = None

    def __post_init__(self) -> None:
        """Update statistics based on issues."""
        self._update_statistics()

    def _update_statistics(self) -> None:
        """Recalculate statistics from issues."""
        self.statistics.total_issues = len(self.issues)
        self.statistics.total_queries = len(self.queries)

        # Reset counts
        for severity in Severity:
            self.statistics.by_severity[severity] = 0
        for dimension in Dimension:
            self.statistics.by_dimension[dimension] = 0

        # Count issues
        for issue in self.issues:
            self.statistics.by_severity[issue.severity] += 1
            self.statistics.by_dimension[issue.dimension] += 1

    def add_issue(self, issue: Issue) -> None:
        """Add an issue and update statistics."""
        self.issues.append(issue)
        self.statistics.total_issues += 1
        self.statistics.by_severity[issue.severity] += 1
        self.statistics.by_dimension[issue.dimension] += 1

    def filter_by_severity(self, *severities: Severity) -> list[Issue]:
        """Filter issues by severity levels."""
        return [i for i in self.issues if i.severity in severities]

    def filter_by_dimension(self, *dimensions: Dimension) -> list[Issue]:
        """Filter issues by dimensions."""
        return [i for i in self.issues if i.dimension in dimensions]

    @property
    def has_critical(self) -> bool:
        """Check if there are any critical issues."""
        return self.statistics.by_severity.get(Severity.CRITICAL, 0) > 0

    @property
    def has_high(self) -> bool:
        """Check if there are any high severity issues."""
        return self.statistics.by_severity.get(Severity.HIGH, 0) > 0

    @property
    def exit_code(self) -> int:
        """
        Determine exit code for CLI based on issues found.

        Returns:
            0: No issues or only INFO
            1: LOW or MEDIUM issues found
            2: HIGH issues found
            3: CRITICAL issues found
        """
        if self.has_critical:
            return 3
        if self.has_high:
            return 2
        if self.statistics.total_issues > self.statistics.by_severity.get(Severity.INFO, 0):
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "issues": [i.to_dict() for i in self.issues],
            "statistics": self.statistics.to_dict(),
            "dialect": self.dialect,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "config_hash": self.config_hash,
        }

    def sorted_by_severity(self) -> list[Issue]:
        """Return issues sorted by severity (most severe first)."""
        return sorted(self.issues, key=lambda i: i.severity, reverse=True)

    def grouped_by_dimension(self) -> dict[Dimension, list[Issue]]:
        """Return issues grouped by dimension."""
        result: dict[Dimension, list[Issue]] = {d: [] for d in Dimension}
        for issue in self.issues:
            result[issue.dimension].append(issue)
        return result

    def grouped_by_file(self) -> dict[str, list[Issue]]:
        """Return issues grouped by file."""
        result: dict[str, list[Issue]] = {}
        for issue in self.issues:
            file_key = issue.location.file or "<stdin>"
            if file_key not in result:
                result[file_key] = []
            result[file_key].append(issue)
        return result
