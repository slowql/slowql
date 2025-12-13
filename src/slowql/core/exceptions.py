# slowql/src/slowql/core/exceptions.py
"""
Custom exceptions for SlowQL.

All SlowQL exceptions inherit from SlowQLError, making it easy to catch
all library-specific exceptions with a single except clause.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slowql.core.models import Location


class SlowQLError(Exception):
    """
    Base exception for all SlowQL errors.

    All other exceptions in this module inherit from this class,
    allowing users to catch all SlowQL-specific exceptions.

    Example:
        >>> try:
        ...     result = analyze(sql)
        ... except SlowQLError as e:
        ...     print(f"SlowQL error: {e}")
    """

    def __init__(self, message: str, *, details: str | None = None) -> None:
        """
        Initialize the exception.

        Args:
            message: The error message.
            details: Optional additional details about the error.
        """
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        """Return string representation."""
        if self.details:
            return f"{self.message}\nDetails: {self.details}"
        return self.message


class ParseError(SlowQLError):
    """
    Raised when SQL parsing fails.

    This exception includes location information when available,
    helping users identify where the parsing error occurred.

    Attributes:
        sql: The SQL that failed to parse.
        location: Optional location of the parse error.
    """

    def __init__(
        self,
        message: str,
        *,
        sql: str | None = None,
        location: Location | None = None,
        details: str | None = None,
    ) -> None:
        """
        Initialize the parse error.

        Args:
            message: The error message.
            sql: The SQL that failed to parse.
            location: Optional location of the error.
            details: Optional additional details.
        """
        super().__init__(message, details=details)
        self.sql = sql
        self.location = location

    def __str__(self) -> str:
        """Return string representation with location info."""
        parts = [self.message]
        if self.location:
            parts.append(f"at line {self.location.line}, column {self.location.column}")
        if self.sql:
            # Show first 100 chars of SQL
            preview = self.sql[:100] + "..." if len(self.sql) > 100 else self.sql
            parts.append(f"SQL: {preview}")
        if self.details:
            parts.append(f"Details: {self.details}")
        return "\n".join(parts)


class AnalysisError(SlowQLError):
    """
    Raised when analysis fails.

    This exception is raised when an analyzer encounters an unexpected
    error during analysis.

    Attributes:
        analyzer_name: Name of the analyzer that failed.
        rule_id: Optional ID of the rule that caused the failure.
    """

    def __init__(
        self,
        message: str,
        *,
        analyzer_name: str | None = None,
        rule_id: str | None = None,
        details: str | None = None,
    ) -> None:
        """
        Initialize the analysis error.

        Args:
            message: The error message.
            analyzer_name: Name of the failing analyzer.
            rule_id: ID of the failing rule, if applicable.
            details: Optional additional details.
        """
        super().__init__(message, details=details)
        self.analyzer_name = analyzer_name
        self.rule_id = rule_id

    def __str__(self) -> str:
        """Return string representation with analyzer info."""
        parts = [self.message]
        if self.analyzer_name:
            parts.append(f"Analyzer: {self.analyzer_name}")
        if self.rule_id:
            parts.append(f"Rule: {self.rule_id}")
        if self.details:
            parts.append(f"Details: {self.details}")
        return "\n".join(parts)


class ConfigurationError(SlowQLError):
    """
    Raised when configuration is invalid.

    This exception is raised when there's an issue with the configuration
    file or configuration values.

    Attributes:
        config_key: The configuration key that caused the error.
        config_value: The invalid value, if applicable.
    """

    def __init__(
        self,
        message: str,
        *,
        config_key: str | None = None,
        config_value: object = None,
        details: str | None = None,
    ) -> None:
        """
        Initialize the configuration error.

        Args:
            message: The error message.
            config_key: The key that caused the error.
            config_value: The invalid value.
            details: Optional additional details.
        """
        super().__init__(message, details=details)
        self.config_key = config_key
        self.config_value = config_value

    def __str__(self) -> str:
        """Return string representation with config info."""
        parts = [self.message]
        if self.config_key:
            parts.append(f"Key: {self.config_key}")
        if self.config_value is not None:
            parts.append(f"Value: {self.config_value!r}")
        if self.details:
            parts.append(f"Details: {self.details}")
        return "\n".join(parts)


class RuleNotFoundError(SlowQLError):
    """
    Raised when a specified rule is not found.

    Attributes:
        rule_id: The ID of the rule that wasn't found.
        available_rules: Optional list of available rule IDs.
    """

    def __init__(
        self,
        rule_id: str,
        *,
        available_rules: list[str] | None = None,
    ) -> None:
        """
        Initialize the rule not found error.

        Args:
            rule_id: The ID that wasn't found.
            available_rules: Optional list of valid rule IDs.
        """
        message = f"Rule not found: {rule_id}"
        super().__init__(message)
        self.rule_id = rule_id
        self.available_rules = available_rules

    def __str__(self) -> str:
        """Return string representation with suggestions."""
        parts = [self.message]
        if self.available_rules:
            # Find similar rules for suggestions
            suggestions = [r for r in self.available_rules if self.rule_id.split("-")[0] in r][:5]
            if suggestions:
                parts.append(f"Did you mean: {', '.join(suggestions)}")
        return "\n".join(parts)


class FileNotFoundError(SlowQLError):
    """
    Raised when a specified file is not found.

    Note: This shadows the builtin FileNotFoundError intentionally
    to provide more context in SlowQL operations.

    Attributes:
        path: The path that wasn't found.
    """

    def __init__(self, path: str) -> None:
        """
        Initialize the file not found error.

        Args:
            path: The path that wasn't found.
        """
        message = f"File not found: {path}"
        super().__init__(message)
        self.path = path


class UnsupportedDialectError(SlowQLError):
    """
    Raised when an unsupported SQL dialect is specified.

    Attributes:
        dialect: The unsupported dialect.
        supported_dialects: List of supported dialects.
    """

    SUPPORTED_DIALECTS: tuple[str, ...] = (
        "postgresql",
        "mysql",
        "sqlite",
        "mssql",
        "oracle",
        "bigquery",
        "snowflake",
        "redshift",
        "clickhouse",
        "duckdb",
        "presto",
        "trino",
        "spark",
    )

    def __init__(self, dialect: str) -> None:
        """
        Initialize the unsupported dialect error.

        Args:
            dialect: The unsupported dialect name.
        """
        message = f"Unsupported SQL dialect: {dialect}"
        super().__init__(message)
        self.dialect = dialect
        self.supported_dialects = self.SUPPORTED_DIALECTS

    def __str__(self) -> str:
        """Return string representation with supported dialects."""
        return (
            f"{self.message}\n"
            f"Supported dialects: {', '.join(self.supported_dialects)}"
        )