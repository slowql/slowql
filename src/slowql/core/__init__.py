# slowql/src/slowql/core/__init__.py
"""
Core module containing the fundamental components of SlowQL.

This module provides:
- Data models for issues, results, and configurations
- The main analysis engine
- Configuration management
- Custom exceptions
"""

from __future__ import annotations

from slowql.core.config import Config
from slowql.core.engine import SlowQL
from slowql.core.exceptions import (
    AnalysisError,
    ConfigurationError,
    ParseError,
    SlowQLError,
)
from slowql.core.models import (
    AnalysisResult,
    Dimension,
    Fix,
    Issue,
    Location,
    Query,
    Severity,
)

__all__ = [
    "AnalysisError",
    "AnalysisResult",
    "Config",
    "ConfigurationError",
    "Dimension",
    "Fix",
    "Issue",
    "Location",
    "ParseError",
    "Query",
    "Severity",
    "SlowQL",
    "SlowQLError",
]
