# slowql/src/slowql/analyzers/__init__.py
"""
SQL analyzers module for SlowQL.

This module provides the analysis engine components:
- Base analyzer class for creating custom analyzers
- Built-in analyzers for security, performance, reliability, etc.
- Analyzer registry for plugin discovery

Analyzers examine parsed SQL queries and detect issues based on
rules and patterns specific to their domain (security, performance, etc.).

Example:
    >>> from slowql.analyzers import AnalyzerRegistry
    >>> registry = AnalyzerRegistry()
    >>> registry.discover()  # Load all analyzers
    >>> for analyzer in registry.get_all():
    ...     print(f"{analyzer.name}: {len(analyzer.rules)} rules")
"""

from __future__ import annotations

from slowql.analyzers.base import BaseAnalyzer, AnalyzerResult
from slowql.analyzers.registry import AnalyzerRegistry

__all__ = [
    "BaseAnalyzer",
    "AnalyzerResult",
    "AnalyzerRegistry",
]