"""
SlowQL Top-level package
"""
from __future__ import annotations

from typing import TYPE_CHECKING

# Define version FIRST to avoid import errors
__version__ = "2.0.0"
__author__ = "makroumi"
__license__ = "Apache-2.0"

from slowql.core.config import Config
from slowql.core.engine import SlowQL
from slowql.core.models import (
    AnalysisResult,
    Dimension,
    Issue,
    Location,
    Severity,
)

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "SlowQL",
    "analyze",
    "analyze_file",
    "AnalysisResult",
    "Issue",
    "Severity",
    "Dimension",
    "Location",
    "Config",
    "__version__",
]

def analyze(
    sql: str,
    *,
    dialect: str | None = None,
    config: Config | None = None,
) -> AnalysisResult:
    engine = SlowQL(config=config)
    return engine.analyze(sql, dialect=dialect)

def analyze_file(
    path: str | Path,
    *,
    dialect: str | None = None,
    config: Config | None = None,
) -> AnalysisResult:
    engine = SlowQL(config=config)
    return engine.analyze_file(path, dialect=dialect)
