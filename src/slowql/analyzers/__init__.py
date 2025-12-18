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

from slowql.analyzers.base import AnalyzerResult, BaseAnalyzer
from slowql.analyzers.compliance import ComplianceAnalyzer
from slowql.analyzers.cost import CostAnalyzer
from slowql.analyzers.performance import PerformanceAnalyzer
from slowql.analyzers.quality import QualityAnalyzer
from slowql.analyzers.registry import AnalyzerRegistry
from slowql.analyzers.reliability import ReliabilityAnalyzer
from slowql.analyzers.security import SecurityAnalyzer

__all__ = [
    "AnalyzerRegistry",
    "AnalyzerResult",
    "BaseAnalyzer",
    "ComplianceAnalyzer",
    "CostAnalyzer",
    "PerformanceAnalyzer",
    "QualityAnalyzer",
    "ReliabilityAnalyzer",
    "SecurityAnalyzer",
]
