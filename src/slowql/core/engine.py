# slowql/src/slowql/core/engine.py
"""
Main analysis engine for SlowQL.

The SlowQL class is the primary interface for analyzing SQL.
It orchestrates parsing, analysis, and result aggregation.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from slowql.analyzers.registry import get_registry
from slowql.core.config import Config
from slowql.core.exceptions import FileNotFoundError, ParseError, SlowQLError
from slowql.core.models import (
    AnalysisResult,
    Issue,
    Query,
)
from slowql.parser.universal import UniversalParser

if TYPE_CHECKING:
    from slowql.analyzers.base import BaseAnalyzer
    from slowql.parser.base import BaseParser


class SlowQL:
    """
    Main SQL analysis engine.

    SlowQL coordinates the analysis process:
    1. Parse SQL into AST using the appropriate dialect parser
    2. Run all enabled analyzers on the parsed queries
    3. Aggregate results and compute statistics

    Example:
        >>> engine = SlowQL()
        >>> result = engine.analyze("SELECT * FROM users")
        >>> for issue in result.issues:
        ...     print(f"{issue.severity}: {issue.message}")

        >>> result = engine.analyze_file("queries.sql")
        >>> print(f"Found {len(result.issues)} issues")

    Attributes:
        config: Configuration for the engine.
        parser: SQL parser instance.
        analyzers: List of enabled analyzers.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        auto_discover: bool = True,
    ) -> None:
        """
        Initialize the SlowQL engine.

        Args:
            config: Configuration to use. If None, will attempt to find
                   and load a configuration file, or use defaults.
            auto_discover: Whether to auto-discover analyzers via entry points.
        """
        self.config = config or Config.find_and_load()
        self._parser: BaseParser | None = None
        self._analyzers: list[BaseAnalyzer] = []
        self._analyzers_loaded = False
        self._auto_discover = auto_discover

    @property
    def parser(self) -> BaseParser:
        """Get the SQL parser, creating it if necessary."""
        if self._parser is None:
            self._parser = UniversalParser(dialect=self.config.analysis.dialect)
        return self._parser

    @property
    def analyzers(self) -> list[BaseAnalyzer]:
        """Get analyzers, loading them if necessary."""
        if not self._analyzers_loaded:
            self._load_analyzers()
            self._analyzers_loaded = True
        return self._analyzers

    def _load_analyzers(self) -> None:
        """Load all enabled analyzers."""
        registry = get_registry()

        if self._auto_discover:
            registry.discover()

        # Filter by enabled dimensions
        enabled = self.config.analysis.enabled_dimensions
        self._analyzers = [
            analyzer for analyzer in registry.get_all() if analyzer.dimension.value in enabled
        ]

    def analyze(
        self,
        sql: str,
        *,
        dialect: str | None = None,
        file_path: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze a SQL string for issues.

        Args:
            sql: The SQL string to analyze. May contain multiple statements.
            dialect: Optional dialect override. If None, uses config or auto-detect.
            file_path: Optional file path for location tracking.

        Returns:
            AnalysisResult containing all detected issues.

        Raises:
            ParseError: If the SQL cannot be parsed.
            AnalysisError: If analysis fails unexpectedly.
        """
        start_time = time.perf_counter()

        # Override dialect if specified
        effective_dialect = dialect or self.config.analysis.dialect

        # Parse SQL
        parse_start = time.perf_counter()
        queries = self._parse_sql(sql, dialect=effective_dialect, file_path=file_path)
        parse_time_ms = (time.perf_counter() - parse_start) * 1000

        # Create result container
        result = AnalysisResult(
            dialect=effective_dialect,
            queries=queries,
            config_hash=self.config.hash(),
        )
        result.statistics.parse_time_ms = parse_time_ms

        # Run analyzers
        issues = self._run_analyzers(queries)

        # Add issues to result
        for issue in issues:
            result.add_issue(issue)

        # Finalize timing
        result.statistics.analysis_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def analyze_file(
        self,
        path: str | Path,
        *,
        dialect: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze a SQL file for issues.

        Args:
            path: Path to the SQL file.
            dialect: Optional dialect override.

        Returns:
            AnalysisResult containing all detected issues.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            ParseError: If the SQL cannot be parsed.
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(str(path))

        sql = path.read_text(encoding="utf-8")

        return self.analyze(sql, dialect=dialect, file_path=str(path))

    def analyze_files(
        self,
        paths: list[str | Path],
        *,
        dialect: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze multiple SQL files.

        Args:
            paths: List of file paths to analyze.
            dialect: Optional dialect override.

        Returns:
            Combined AnalysisResult from all files.
        """
        combined_result = AnalysisResult(
            dialect=dialect or self.config.analysis.dialect,
            config_hash=self.config.hash(),
        )

        for path in paths:
            try:
                result = self.analyze_file(path, dialect=dialect)
                combined_result.queries.extend(result.queries)
                for issue in result.issues:
                    combined_result.add_issue(issue)
                combined_result.statistics.parse_time_ms += result.statistics.parse_time_ms
            except SlowQLError:
                # Re-raise SlowQL errors
                raise
            except Exception as e:
                # Wrap unexpected errors
                raise ParseError(
                    f"Failed to analyze file: {path}",
                    details=str(e),
                ) from e

        return combined_result

    def _parse_sql(
        self,
        sql: str,
        *,
        dialect: str | None = None,
        file_path: str | None = None,
    ) -> list[Query]:
        """
        Parse SQL into Query objects.
        """
        # Check query length limit
        if len(sql) > self.config.analysis.max_query_length:
            raise ParseError(
                f"Query exceeds maximum length of {self.config.analysis.max_query_length}",
                sql=sql[:100] + "...",
            )

        return self.parser.parse(sql, dialect=dialect, file_path=file_path)

    def _run_analyzers(self, queries: list[Query]) -> list[Issue]:
        """
        Run all enabled analyzers on queries.
        """
        issues: list[Issue] = []

        for analyzer in self.analyzers:
            # Check if analyzer should run based on config
            if not self._should_run_analyzer(analyzer):
                continue

            # Run analyzer on each query
            for query in queries:
                analyzer_issues = analyzer.analyze(query, config=self.config)

                # Filter issues by rule configuration
                for issue in analyzer_issues:
                    if self._should_report_issue(issue):
                        issues.append(issue)

        return issues

    def _should_run_analyzer(self, analyzer: BaseAnalyzer) -> bool:
        """Check if an analyzer should run based on configuration."""
        return analyzer.dimension.value in self.config.analysis.enabled_dimensions

    def _should_report_issue(self, issue: Issue) -> bool:
        """Check if an issue should be reported based on configuration."""
        config = self.config.analysis

        # Check enabled_rules (whitelist mode)
        if config.enabled_rules is not None and issue.rule_id not in config.enabled_rules:
            # Also check rule prefix
            prefix = "-".join(issue.rule_id.split("-")[:2])
            if prefix not in config.enabled_rules:
                return False

        # Check disabled_rules (blacklist mode)
        if issue.rule_id in config.disabled_rules:
            return False

        # Check prefix disable
        prefix = "-".join(issue.rule_id.split("-")[:2])
        return prefix not in config.disabled_rules

    def get_rule_info(self, rule_id: str) -> dict[str, Any] | None:
        """
        Get information about a specific rule.

        Note: Currently relies on analyzer inspection as explicit rule registry
        isn't fully populated in this version.
        """
        # Iterate over all loaded analyzers to find the rule
        for analyzer in self.analyzers:
            for rule in analyzer.rules:
                if rule.id == rule_id:
                    # Construct info manually if metadata not available
                    return {
                        "id": rule.id,
                        "name": getattr(rule, "name", ""),
                        "description": getattr(rule, "description", ""),
                        "severity": getattr(rule, "severity", ""),
                        "dimension": getattr(rule, "dimension", ""),
                    }
        return None

    def list_rules(self) -> list[dict[str, Any]]:
        """
        List all available rules.
        """
        rules = []
        for analyzer in self.analyzers:
            for rule in analyzer.rules:
                rules.append(
                    {
                        "id": rule.id,
                        "name": getattr(rule, "name", ""),
                        "dimension": getattr(rule, "dimension", ""),
                    }
                )
        return rules
