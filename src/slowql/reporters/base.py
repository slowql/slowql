# slowql/src/slowql/reporters/base.py
"""
Base reporter class for SlowQL.

This module defines the abstract interface for all reporters.
Reporters are responsible for taking analysis results and formatting
them for different outputs (Console, JSON, HTML, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, TextIO


if TYPE_CHECKING:
    from slowql.core.models import AnalysisResult


class BaseReporter(ABC):
    """
    Abstract base class for all reporters.

    Attributes:
        output_file: Optional file handle to write to (default: stdout).
    """

    def __init__(self, output_file: TextIO | None = None) -> None:
        """
        Initialize the reporter.

        Args:
            output_file: Output stream (file-like object).
        """
        self.output_file = output_file

    @abstractmethod
    def report(self, result: AnalysisResult) -> None:
        """
        Generate and output the report.

        Args:
            result: The analysis result to report on.
        """
        ...