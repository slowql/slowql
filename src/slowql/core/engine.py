# slowql/src/slowql/core/engine.py
"""
Main analysis engine for SlowQL.

The SlowQL class is the primary interface for analyzing SQL.
It orchestrates parsing, analysis, and result aggregation.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
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
from slowql.core.suppressions import parse_suppressions
from slowql.parser.universal import UniversalParser
from slowql.schema.inspector import SchemaInspector

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from slowql.analyzers.base import BaseAnalyzer
    from slowql.parser.base import BaseParser
    from slowql.schema.models import Schema


def _analyze_file_worker(payload: dict[str, Any]) -> tuple[str, AnalysisResult | Exception]:
    """Top-level worker function for parallel file analysis."""
    path = payload["path"]
    dialect = payload["dialect"]
    config_dict = payload["config_dict"]
    schema = payload["schema"]

    try:
        config = Config.model_validate(config_dict)
        engine = SlowQL(config=config, schema=schema)
        result = engine.analyze_file(path, dialect=dialect)
        return str(path), result
    except Exception as e:
        return str(path), e


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
        schema: Schema | None = None,
        schema_path: str | Path | None = None,
    ) -> None:
        """
        Initialize the SlowQL engine.

        Args:
            config: Configuration to use. If None, will attempt to find
                   and load a configuration file, or use defaults.
            auto_discover: Whether to auto-discover analyzers via entry points.
            schema: Optional pre-loaded Schema object.
            schema_path: Optional path to a DDL file to load schema from.
        """
        self.config = config or Config.find_and_load()
        self._parser: BaseParser | None = None
        self._analyzers: list[BaseAnalyzer] = []
        self._analyzers_loaded = False
        self._auto_discover = auto_discover
        self._schema: Schema | None = None

        # Load schema if provided
        if schema is not None:
            self._schema = schema
        elif schema_path is not None:
            self._schema = self._load_schema(schema_path)
        elif self.config.schema_config.path is not None:
            self._schema = self._load_schema(self.config.schema_config.path)

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

    @property
    def schema(self) -> Schema | None:
        """Get the loaded schema, if any."""
        return self._schema

    @schema.setter
    def schema(self, value: Schema | None) -> None:
        """Set the schema for validation."""
        self._schema = value

    def _load_schema(self, path: str | Path) -> Schema:
        """Load schema from DDL file."""
        return SchemaInspector.from_ddl_file(
            path, dialect=self.config.analysis.dialect or "postgresql"
        )

    def _extract_ddl_schema(self, sql: str, dialect: str | None = None) -> Schema | None:
        """
        Extract schema from DDL statements embedded in sql.

        Scans the sql string for CREATE TABLE statements using a simple
        regex. If any are found, parses them with DDLParser and returns
        a Schema. Returns None if no CREATE TABLE statements are found.

        This is intentionally conservative — it only triggers on
        CREATE TABLE, not CREATE VIEW, CREATE INDEX, etc.
        """
        if not re.search(r"\bCREATE\s+TABLE\b", sql, re.IGNORECASE):
            return None

        try:
            effective_dialect = dialect or self.config.analysis.dialect or "postgresql"
            return SchemaInspector.from_ddl_string(sql, dialect=effective_dialect)
        except Exception:
            # Never crash analysis because DDL parsing failed
            logger.warning("DDL auto-detection failed — schema rules will not run")
            return None

    def with_schema(
        self, schema: Schema | None = None, schema_path: str | Path | None = None
    ) -> SlowQL:
        """Return a new engine instance with schema loaded."""
        if schema is not None:
            self._schema = schema
        elif schema_path is not None:
            self._schema = self._load_schema(schema_path)
        return self

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

        # Load user-defined custom rules via the plugin system
        plugin_cfg = self.config.plugins
        if plugin_cfg.directories or plugin_cfg.modules:
            self._load_plugin_rules(plugin_cfg)

    def _load_plugin_rules(self, plugin_cfg: Any) -> None:
        """Load custom rules from plugin directories and modules."""
        from slowql.analyzers.base import RuleBasedAnalyzer  # noqa: PLC0415
        from slowql.core.models import Dimension  # noqa: PLC0415
        from slowql.plugins.manager import PluginManager  # noqa: PLC0415

        mgr = PluginManager(
            directories=list(plugin_cfg.directories),
            modules=list(plugin_cfg.modules),
        )
        rules = mgr.load_rules()

        if not rules:
            return

        # Group rules by dimension so each dimension gets its own analyzer
        dimension_rules: dict[str, list[Any]] = {}
        for rule in rules:
            dim_value = rule.dimension.value
            dimension_rules.setdefault(dim_value, []).append(rule)

        for dim_value, dim_rules in dimension_rules.items():
            # Build a concrete RuleBasedAnalyzer subclass dynamically
            captured_rules = list(dim_rules)

            class _CustomAnalyzer(RuleBasedAnalyzer):
                name = f"custom-{dim_value}"
                description = f"User-defined custom rules for {dim_value}"
                priority = 200  # run after built-in analyzers

                def get_rules(
                    self, _rules: list[Any] = captured_rules
                ) -> list[Any]:
                    return _rules

            try:
                dimension = Dimension(dim_value)
            except ValueError:
                logger.warning("Unknown dimension %r for custom rules — skipped.", dim_value)
                continue

            _CustomAnalyzer.dimension = dimension
            analyzer_instance = _CustomAnalyzer()
            self._analyzers.append(analyzer_instance)

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

        # Auto-detect schema from DDL statements in the input
        if self._schema is None:
            detected = self._extract_ddl_schema(sql, dialect=effective_dialect)
            if detected is not None:
                self._schema = detected

        # Create result container
        result = AnalysisResult(
            dialect=effective_dialect,
            queries=queries,
            config_hash=self.config.hash(),
        )
        result.statistics.parse_time_ms = parse_time_ms

        # Run analyzers
        raw_issues = self._run_analyzers(queries)

        # Apply inline suppression directives
        suppressed_count = 0
        suppression_map = parse_suppressions(sql)
        issues: list[Issue] = []
        for issue in raw_issues:
            if suppression_map.is_suppressed(issue.location.line, issue.rule_id):
                suppressed_count += 1
            else:
                issues.append(issue)

        # Add surviving issues to result
        for issue in issues:
            result.add_issue(issue)

        result.suppressed_count = suppressed_count

        # Finalize timing
        result.statistics.analysis_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def analyze_file(
        self,
        path: str | Path,
        *,
        dialect: str | None = None,
        use_cache: bool = True,
    ) -> AnalysisResult:
        """
        Analyze a SQL file for issues.

        Args:
            path: Path to the SQL file.
            dialect: Optional dialect override.
            use_cache: Whether to use caching if enabled in config.

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

        # Try cache
        cache_manager = None
        if use_cache and self.config.cache_config.enabled:
            from slowql.core.cache import CacheManager  # noqa: PLC0415
            cache_manager = CacheManager(self.config.cache_config.dir)
            cached_result = cache_manager.get(path, sql, self.config.hash())
            if cached_result is not None:
                return cached_result

        result = self.analyze(sql, dialect=dialect, file_path=str(path))

        if cache_manager is not None:
            cache_manager.set(path, sql, self.config.hash(), result)

        return result

    def analyze_migrations(self, path: str | Path) -> AnalysisResult:
        """
        Analyze database migrations in the given path.
        Args:
            path: Path to the migration directory or project root.

        Returns:
            AnalysisResult containing issues found in migrations.
        """
        from slowql.migrations.discovery import MigrationDiscovery  # noqa: PLC0415
        from slowql.migrations.tracker import MigrationSchemaTracker  # noqa: PLC0415

        path = Path(path)
        discovery = MigrationDiscovery.default()
        migrations = discovery.get_migrations(path)

        if not migrations:
            return AnalysisResult(dialect=self.config.analysis.dialect, config_hash=self.config.hash())

        tracker = MigrationSchemaTracker(initial_schema=self._schema)
        # We need to compute history based on migration sequence
        # For simplicity in this implementation, we apply them one by one

        combined_result = AnalysisResult(
            dialect=self.config.analysis.dialect,
            config_hash=self.config.hash()
        )

        current_schema = self._schema
        for migration in migrations:
            # Parse the migration content
            queries = self._parse_sql(
                migration.content,
                dialect=self.config.analysis.dialect,
                file_path=str(migration.path)
            )

            # Run migration-specific rules (breaking changes)
            if current_schema:
                migration_issues = self._run_migration_rules(queries, current_schema)
                for issue in migration_issues:
                    combined_result.add_issue(issue)

            # Run normal analyzers on the migration SQL
            old_schema = self._schema
            self._schema = current_schema
            try:
                raw_issues = self._run_analyzers(queries)
                for issue in raw_issues:
                    combined_result.add_issue(issue)
            finally:
                self._schema = old_schema

            combined_result.queries.extend(queries)

            # Update tracker and current_schema for the NEXT migration
            for query in queries:
                if query.is_ddl and current_schema:
                    tracker.apply_ddl(migration.content) # Ensure tracker stays in sync
                    from slowql.schema.ddl_parser import DDLParser  # noqa: PLC0415
                    DDLParser.apply_ddl(current_schema, query.sql, dialect=query.dialect)

        return combined_result

    def analyze_with_baseline(
        self,
        path: str | Path,
        baseline_path: str | Path,
        *,
        dialect: str | None = None,
    ) -> tuple[AnalysisResult, int]:
        """
        Analyze a file and suppress issues present in the baseline.

        Args:
            path: Path to the SQL file.
            baseline_path: Path to the .slowql-baseline file.
            dialect: Optional dialect override.

        Returns:
            A tuple of (AnalysisResult, suppressed_count). The result contains
            ONLY issues that are NOT in the baseline. The suppressed_count tells
            how many issues were hidden by the baseline.

        Raises:
            FileNotFoundError: If the input file or baseline file doesn't exist.
            ParseError: If the SQL cannot be parsed.
        """
        from slowql.core.baseline import BaselineManager  # noqa: PLC0415

        # Raise FileNotFoundError early if baseline is missing
        baseline = BaselineManager.load(Path(baseline_path))

        # Perform the actual run
        full_result = self.analyze_file(path, dialect=dialect)

        # Filter out baseline issues
        filtered_result, baseline_suppressed_count = BaselineManager.filter_new(
            full_result, baseline
        )

        return filtered_result, baseline_suppressed_count

    def analyze_files(  # noqa: PLR0912
        self,
        paths: Sequence[str | Path],
        *,
        dialect: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze multiple SQL files.
        """
        combined_result = AnalysisResult(
            dialect=dialect or self.config.analysis.dialect,
            config_hash=self.config.hash(),
        )

        # First pass: accumulate all SQL to extract schema across files
        if self._schema is None:
            all_sql_parts = []
            for path in paths:
                try:
                    p = Path(path).resolve()
                    if p.is_file():
                        all_sql_parts.append(p.read_text(encoding="utf-8"))
                    elif p.is_dir():
                        # We don't read directories as SQL text directly
                        pass
                except Exception:
                    pass
            if all_sql_parts:
                detected = self._extract_ddl_schema(
                    "\n".join(all_sql_parts),
                    dialect=dialect or self.config.analysis.dialect,
                )
                if detected is not None:
                    self._schema = detected

        # Second pass: analyze each file with shared schema
        # Filter out migration projects from parallel processing
        regular_paths = []
        migration_results = []
        
        from slowql.migrations.discovery import MigrationDiscovery # noqa: PLC0415
        discovery = MigrationDiscovery.default()

        for path in paths:
            p = Path(path).resolve()
            if p.is_dir():
                framework = discovery.detect_framework(p)
                if framework:
                    m_result = self.analyze_migrations(p)
                    migration_results.append(m_result)
                else:
                    logger.info(f"Skipping directory {path}: not a migration project.")
            else:
                regular_paths.append(path)

        # Handle regular files
        if self.config.analysis.parallel and len(regular_paths) > 1:
            max_workers = self.config.analysis.max_workers
            if not max_workers or max_workers <= 0:
                max_workers = os.cpu_count() or 4

            config_dump = self.config.model_dump()
            payloads = [
                {
                    "path": str(p),
                    "dialect": dialect,
                    "config_dict": config_dump,
                    "schema": self._schema,
                }
                for p in regular_paths
            ]

            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                for path_str, result_or_exc in executor.map(_analyze_file_worker, payloads):
                    if isinstance(result_or_exc, (SlowQLError, FileNotFoundError)):
                        logger.warning(f"Skipping file due to error: {path_str}")
                    elif isinstance(result_or_exc, Exception):
                        raise ParseError(
                            f"Failed to analyze file: {path_str}",
                            details=str(result_or_exc),
                        ) from result_or_exc
                    else:
                        combined_result.queries.extend(result_or_exc.queries)
                        combined_result.statistics.total_queries += len(result_or_exc.queries)
                        for issue in result_or_exc.issues:
                            combined_result.add_issue(issue)
                        combined_result.statistics.parse_time_ms += result_or_exc.statistics.parse_time_ms
        else:
            for path in regular_paths:
                try:
                    res = self.analyze_file(path, dialect=dialect)
                    combined_result.issues.extend(res.issues)
                    combined_result.queries.extend(res.queries)
                    combined_result.statistics.total_queries += len(res.queries)
                    combined_result.statistics.parse_time_ms += res.statistics.parse_time_ms
                except (SlowQLError, FileNotFoundError):
                    # Skip files that don't exist or have known errors during batch analysis
                    logger.warning(f"Skipping file due to error: {path}")
                    continue
                except Exception as e:
                    # Wrap unexpected errors
                    raise ParseError(
                        f"Failed to analyze file: {path}",
                        details=str(e),
                    ) from e

        # Finalize results with migration issues
        for m_result in migration_results:
            combined_result.issues.extend(m_result.issues)
            combined_result.queries.extend(m_result.queries)
            combined_result.statistics.total_queries += len(m_result.queries)
            combined_result.statistics.parse_time_ms += m_result.statistics.parse_time_ms

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

        # Run schema-aware rules if schema is loaded
        if self._schema is not None:
            schema_issues = self._run_schema_rules(queries)
            issues.extend(schema_issues)

        return self._apply_severity_overrides(issues)

    def _run_migration_rules(self, queries: list[Query], schema_before: Schema) -> list[Issue]:
        """Run migration-specific validation rules."""
        from slowql.rules.migration.breaking_change import BreakingChangeRule  # noqa: PLC0415

        issues: list[Issue] = []
        rule = BreakingChangeRule(schema_before)

        for query in queries:
            try:
                rule_issues = rule.check(query)
                for issue in rule_issues:
                    if self._should_report_issue(issue):
                        issues.append(issue)
            except Exception as e:
                logger.warning(f"Migration rule failed: {e}")

        return self._apply_severity_overrides(issues)

    def _run_schema_rules(self, queries: list[Query]) -> list[Issue]:
        """Run schema-aware validation rules."""
        if self._schema is None:
            return []

        # Help mypy understand _schema is not None
        schema = self._schema

        from slowql.rules.schema import (  # noqa: PLC0415
            ColumnExistsRule,
            MissingIndexRule,
            TableExistsRule,
        )

        issues: list[Issue] = []

        rules = [
            TableExistsRule(schema),
            ColumnExistsRule(schema),
            MissingIndexRule(schema),
        ]

        for query in queries:
            for rule in rules:
                try:
                    rule_issues = rule.check(query)
                    for issue in rule_issues:
                        if self._should_report_issue(issue):
                            issues.append(issue)
                except Exception as e:
                    # Log but don't crash on rule errors
                    logger.warning(f"Schema rule {rule.id} failed: {e}")

        return self._apply_severity_overrides(issues)

    def _apply_severity_overrides(self, issues: list[Issue]) -> list[Issue]:
        """Apply severity overrides from configuration."""
        overrides = self.config.analysis.severity_overrides
        if not overrides:
            return issues

        overridden_issues = []
        for issue in issues:
            if issue.rule_id in overrides:
                # Create a new issue with overridden severity
                new_issue = Issue(
                    rule_id=issue.rule_id,
                    message=issue.message,
                    severity=overrides[issue.rule_id],
                    dimension=issue.dimension,
                    category=issue.category,
                    location=issue.location,
                    snippet=issue.snippet,
                    fix=issue.fix,
                    impact=issue.impact,
                    documentation_url=issue.documentation_url,
                    tags=issue.tags,
                    metadata=issue.metadata,
                )
                overridden_issues.append(new_issue)
            else:
                overridden_issues.append(issue)

        return overridden_issues

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
