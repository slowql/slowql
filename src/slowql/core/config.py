# slowql/src/slowql/core/config.py
"""
Configuration management for SlowQL.

This module provides a flexible configuration system that supports:
- Default configuration
- Configuration files (TOML, YAML, JSON)
- Environment variables
- Programmatic configuration

Configuration is validated using Pydantic for type safety.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal

import tomli
from pydantic import BaseModel, ConfigDict, Field, field_validator

from slowql.core.exceptions import ConfigurationError

yaml: Any | None
try:
    import yaml
except ImportError:
    yaml = None


class SeverityThresholds(BaseModel):
    """Configuration for severity-based behavior."""

    fail_on: Literal["critical", "high", "medium", "low", "info", "never"] = "high"
    """Minimum severity level that causes non-zero exit code."""

    warn_on: Literal["critical", "high", "medium", "low", "info", "never"] = "medium"
    """Minimum severity level that triggers warnings."""

    model_config = ConfigDict(frozen=True)


class OutputConfig(BaseModel):
    """Configuration for output behavior."""

    format: Literal["text", "json", "html", "sarif", "csv"] = "text"
    """Output format."""

    color: bool = True
    """Enable colored output."""

    verbose: bool = False
    """Enable verbose output with additional details."""

    quiet: bool = False
    """Suppress all output except errors."""

    show_fixes: bool = True
    """Show suggested fixes for issues."""

    show_snippets: bool = True
    """Show code snippets for issues."""

    max_issues: int = 0
    """Maximum number of issues to display (0 = unlimited)."""

    group_by: Literal["severity", "dimension", "file", "rule", "none"] = "severity"
    """How to group issues in output."""

    model_config = ConfigDict(frozen=True)


class AnalysisConfig(BaseModel):
    """Configuration for analysis behavior."""

    dialect: str | None = None
    """SQL dialect to use (auto-detect if None)."""

    enabled_dimensions: set[str] = Field(
        default_factory=lambda: {
            "security",
            "performance",
            "reliability",
            "compliance",
            "cost",
            "quality",
        }
    )
    """Which dimensions to analyze."""

    disabled_rules: set[str] = Field(default_factory=set)
    """Rule IDs to skip."""

    enabled_rules: set[str] | None = None
    """If set, only run these rules (overrides disabled_rules)."""

    max_query_length: int = 100_000
    """Maximum query length to analyze (characters)."""

    timeout_seconds: float = 30.0
    """Timeout for analyzing a single query."""

    parallel: bool = True
    """Enable parallel analysis."""

    max_workers: int = 0
    """Number of parallel workers (0 = auto based on CPU count)."""

    model_config = ConfigDict(frozen=True)

    @field_validator("enabled_dimensions", "disabled_rules", mode="before")
    @classmethod
    def _validate_str_list_to_set(cls, v: Any) -> set[str] | Any:
        """Convert list to set if needed."""
        if isinstance(v, list):
            return set(v)
        return v


class ComplianceConfig(BaseModel):
    """Configuration for compliance-specific analysis."""

    frameworks: set[str] = Field(default_factory=set)
    """Compliance frameworks to check (gdpr, hipaa, pci-dss, sox, soc2)."""

    strict_mode: bool = False
    """Enable strict compliance checking."""

    model_config = ConfigDict(frozen=True)


class CostConfig(BaseModel):
    """Configuration for cost estimation."""

    cloud_provider: Literal["aws", "gcp", "azure", "snowflake", "databricks", "none"] = "none"
    """Cloud provider for cost estimation."""

    compute_cost_per_hour: float = 0.0
    """Cost per compute hour in USD."""

    storage_cost_per_gb: float = 0.0
    """Cost per GB of storage in USD."""

    data_transfer_cost_per_gb: float = 0.0
    """Cost per GB of data transfer in USD."""

    model_config = ConfigDict(frozen=True)


class Config(BaseModel):
    """
    Main configuration for SlowQL.

    This class aggregates all configuration options and provides
    methods for loading from various sources.

    Example:
        >>> config = Config()  # Use defaults
        >>> config = Config.from_file("slowql.toml")
        >>> config = Config(analysis=AnalysisConfig(dialect="postgresql"))
    """

    severity: SeverityThresholds = Field(default_factory=SeverityThresholds)
    """Severity threshold configuration."""

    output: OutputConfig = Field(default_factory=OutputConfig)
    """Output configuration."""

    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    """Analysis configuration."""

    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    """Compliance configuration."""

    cost: CostConfig = Field(default_factory=CostConfig)
    """Cost estimation configuration."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """
        Load configuration from a file.

        Supports TOML, YAML, and JSON formats based on file extension.

        Args:
            path: Path to configuration file.

        Returns:
            Loaded configuration.

        Raises:
            ConfigurationError: If file cannot be loaded or parsed.
        """
        path = Path(path)

        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")

        suffix = path.suffix.lower()

        try:
            if suffix == ".toml":
                data = tomli.loads(path.read_text(encoding="utf-8"))
            elif suffix in {".yaml", ".yml"}:
                if yaml is None:  # pragma: no cover
                    raise ConfigurationError(
                        "PyYAML is required for YAML config files",
                        details="Install with: pip install pyyaml",
                    )
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            elif suffix == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
            else:
                raise ConfigurationError(
                    f"Unsupported configuration file format: {suffix}",
                    details="Supported formats: .toml, .yaml, .yml, .json",
                )

            return cls.model_validate(data)

        except Exception as e:
            if isinstance(e, ConfigurationError):
                raise
            raise ConfigurationError(
                f"Failed to parse configuration file: {path}",
                details=str(e),
            ) from e

    @classmethod
    def from_env(cls) -> Config:
        """
        Load configuration from environment variables.

        Environment variables are prefixed with SLOWQL_ and use
        double underscores for nesting.

        Example:
            SLOWQL_OUTPUT__FORMAT=json
            SLOWQL_ANALYSIS__DIALECT=postgresql
            SLOWQL_SEVERITY__FAIL_ON=critical

        Returns:
            Configuration loaded from environment.
        """
        data: dict[str, Any] = {}

        prefix = "SLOWQL_"

        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue

            # Remove prefix and split by double underscore
            key_path = key[len(prefix) :].lower().split("__")

            # Navigate/create nested dict
            current = data
            for part in key_path[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Set value (try to parse as appropriate type)
            final_key = key_path[-1]
            current[final_key] = cls._parse_env_value(value)

        return cls.model_validate(data)

    @staticmethod
    def _parse_env_value(value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Boolean
        if value.lower() in {"true", "1", "yes", "on"}:
            return True
        if value.lower() in {"false", "0", "no", "off"}:
            return False

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # NOTE: This is a simple parser for comma-separated lists.
        if "," in value:
            return [v.strip() for v in value.split(",")]

        return value

    @classmethod
    def find_and_load(cls, start_path: Path | None = None) -> Config:
        """
        Find and load configuration file from current or parent directories.

        Searches for configuration files in this order:
        1. slowql.toml
        2. .slowql.toml
        3. pyproject.toml (under [tool.slowql] section)
        4. slowql.yaml / slowql.yml
        5. .slowql.yaml / .slowql.yml

        Args:
            start_path: Directory to start searching from (default: cwd).

        Returns:
            Loaded configuration or defaults if no config file found.
        """
        if start_path is None:
            start_path = Path.cwd()

        config_names = [
            "slowql.toml",
            ".slowql.toml",
            "slowql.yaml",
            "slowql.yml",
            ".slowql.yaml",
            ".slowql.yml",
            "slowql.json",
            ".slowql.json",
        ]

        # Search current and parent directories
        current = start_path.resolve()
        while current != current.parent:
            for name in config_names:
                config_path = current / name
                if config_path.exists():
                    return cls.from_file(config_path)

            # Check pyproject.toml
            pyproject = current / "pyproject.toml"
            if pyproject.exists():
                config = cls._load_from_pyproject(pyproject)
                if config is not None:
                    return config

            current = current.parent

        # No config file found, use defaults merged with env
        return cls.from_env()

    @classmethod
    def _load_from_pyproject(cls, path: Path) -> Config | None:
        """Load configuration from pyproject.toml [tool.slowql] section."""
        data = tomli.loads(path.read_text(encoding="utf-8"))

        tool_config = data.get("tool", {}).get("slowql")
        if tool_config:
            return cls.model_validate(tool_config)

        return None

    def with_overrides(self, **kwargs: Any) -> Config:
        """
        Create a new configuration with overrides.

        Args:
            **kwargs: Configuration values to override.

        Returns:
            New configuration with overrides applied.

        Example:
            >>> config = Config()
            >>> new_config = config.with_overrides(
            ...     output={"format": "json"},
            ...     analysis={"dialect": "mysql"}
            ... )
        """
        data = self.model_dump()

        for key, value in kwargs.items():
            if isinstance(value, dict) and key in data and isinstance(data[key], dict):
                data[key].update(value)
            else:
                data[key] = value

        return Config.model_validate(data)

    def hash(self) -> str:
        """
        Generate a hash of the configuration for reproducibility.

        Returns:
            Hex string hash of the configuration.
        """
        config_str = json.dumps(self.model_dump(), sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]
