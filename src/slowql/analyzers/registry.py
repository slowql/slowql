# slowql/src/slowql/analyzers/registry.py
"""
Analyzer registry for SlowQL.

This module provides a registry for managing and discovering analyzers.
Analyzers can be registered programmatically or discovered via entry points.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, Callable, Iterator

from slowql.core.models import Dimension

if TYPE_CHECKING:
    from slowql.analyzers.base import BaseAnalyzer


class AnalyzerRegistry:
    """
    Registry for managing SQL analyzers.

    The registry supports:
    - Manual registration of analyzers
    - Auto-discovery via entry points
    - Filtering by dimension
    - Priority-based ordering

    Example:
        >>> registry = AnalyzerRegistry()
        >>> registry.discover()  # Load all analyzers from entry points
        >>>
        >>> # Get all analyzers
        >>> for analyzer in registry.get_all():
        ...     print(analyzer.name)
        >>>
        >>> # Get security analyzers only
        >>> security = registry.get_by_dimension(Dimension.SECURITY)
        >>>
        >>> # Register a custom analyzer
        >>> registry.register(MyCustomAnalyzer())
    """

    # Entry point group for analyzer discovery
    ENTRY_POINT_GROUP = "slowql.analyzers"

    def __init__(self) -> None:
        """Initialize the registry."""
        self._analyzers: dict[str, BaseAnalyzer] = {}
        self._discovered = False

    def register(
        self,
        analyzer: BaseAnalyzer,
        *,
        replace: bool = False,
    ) -> None:
        """
        Register an analyzer.

        Args:
            analyzer: The analyzer instance to register.
            replace: If True, replace existing analyzer with same name.

        Raises:
            ValueError: If analyzer with same name exists and replace=False.
        """
        name = analyzer.name

        if name in self._analyzers and not replace:
            raise ValueError(
                f"Analyzer '{name}' is already registered. "
                f"Use replace=True to override."
            )

        self._analyzers[name] = analyzer

    def unregister(self, name: str) -> BaseAnalyzer | None:
        """
        Unregister an analyzer by name.

        Args:
            name: The analyzer name to unregister.

        Returns:
            The removed analyzer, or None if not found.
        """
        return self._analyzers.pop(name, None)

    def get(self, name: str) -> BaseAnalyzer | None:
        """
        Get an analyzer by name.

        Args:
            name: The analyzer name.

        Returns:
            The analyzer instance, or None if not found.
        """
        return self._analyzers.get(name)

    def get_all(self) -> list[BaseAnalyzer]:
        """
        Get all registered analyzers.

        Returns:
            List of analyzers sorted by priority.
        """
        return sorted(
            self._analyzers.values(),
            key=lambda a: (a.priority, a.name),
        )

    def get_by_dimension(self, dimension: Dimension) -> list[BaseAnalyzer]:
        """
        Get analyzers for a specific dimension.

        Args:
            dimension: The dimension to filter by.

        Returns:
            List of matching analyzers sorted by priority.
        """
        return sorted(
            (a for a in self._analyzers.values() if a.dimension == dimension),
            key=lambda a: (a.priority, a.name),
        )

    def get_enabled(self) -> list[BaseAnalyzer]:
        """
        Get all enabled analyzers.

        Returns:
            List of enabled analyzers sorted by priority.
        """
        return sorted(
            (a for a in self._analyzers.values() if a.enabled),
            key=lambda a: (a.priority, a.name),
        )

    def discover(self) -> int:
        """
        Discover and register analyzers from entry points.

        This method loads analyzers from the 'slowql.analyzers' entry point
        group. Each entry point should point to an analyzer class.

        Returns:
            Number of analyzers discovered.

        Example pyproject.toml entry:
            [project.entry-points."slowql.analyzers"]
            security = "slowql.analyzers.security:SecurityAnalyzer"
            performance = "slowql.analyzers.performance:PerformanceAnalyzer"
        """
        if self._discovered:
            return len(self._analyzers)

        count = 0

        # Use importlib.metadata for entry point discovery
        # sys.version_info is safe to use here as sys is imported at module level
        if sys.version_info >= (3, 10):
            from importlib.metadata import entry_points
            # Python 3.10+ returns EntryPoints object which is selectable
            eps = entry_points(group=self.ENTRY_POINT_GROUP)
        else:
            from importlib.metadata import entry_points
            # Python < 3.10 returns dict
            all_eps = entry_points()
            eps = all_eps.get(self.ENTRY_POINT_GROUP, [])

        for ep in eps:
            try:
                analyzer_class = ep.load()

                # Instantiate if it's a class
                if isinstance(analyzer_class, type):
                    analyzer = analyzer_class()
                else:
                    analyzer = analyzer_class

                self.register(analyzer)
                count += 1

            except Exception as e:
                # Log warning but continue
                print(
                    f"Warning: Failed to load analyzer '{ep.name}': {e}",
                    file=sys.stderr,
                )

        # Also load built-in analyzers
        count += self._load_builtin_analyzers()

        self._discovered = True
        return count

    def _load_builtin_analyzers(self) -> int:
        """Load built-in analyzers."""
        count = 0

        # Import built-in analyzers using dynamic imports to avoid circular deps
        # or heavy import times at startup
        builtin_modules = [
            ("slowql.analyzers.security", "SecurityAnalyzer"),
            ("slowql.analyzers.performance", "PerformanceAnalyzer"),
            ("slowql.analyzers.reliability", "ReliabilityAnalyzer"),
            ("slowql.analyzers.compliance", "ComplianceAnalyzer"),
            ("slowql.analyzers.cost", "CostAnalyzer"),
            ("slowql.analyzers.quality", "QualityAnalyzer"),
        ]

        for module_name, class_name in builtin_modules:
            try:
                module = __import__(module_name, fromlist=[class_name])
                analyzer_class = getattr(module, class_name, None)

                if analyzer_class is not None:
                    # Instantiate
                    analyzer = analyzer_class()
                    # Only register if not already present (allows overrides)
                    if analyzer.name not in self._analyzers:
                        self.register(analyzer)
                        count += 1

            except ImportError:
                # Module not yet implemented - skip silently
                pass
            except Exception as e:
                print(
                    f"Warning: Failed to load built-in analyzer "
                    f"'{module_name}.{class_name}': {e}",
                    file=sys.stderr,
                )

        return count

    def __len__(self) -> int:
        """Return number of registered analyzers."""
        return len(self._analyzers)

    def __iter__(self) -> Iterator[BaseAnalyzer]:
        """Iterate over all analyzers."""
        return iter(self.get_all())

    def __contains__(self, name: str) -> bool:
        """Check if an analyzer is registered."""
        return name in self._analyzers

    def list_names(self) -> list[str]:
        """Get list of all analyzer names."""
        return list(self._analyzers.keys())

    def list_dimensions(self) -> list[Dimension]:
        """Get list of dimensions with registered analyzers."""
        return list(set(a.dimension for a in self._analyzers.values()))

    def clear(self) -> None:
        """Clear all registered analyzers."""
        self._analyzers.clear()
        self._discovered = False

    def stats(self) -> dict[str, Any]:
        """
        Get statistics about registered analyzers.

        Returns:
            Dictionary with analyzer statistics.
        """
        by_dimension: dict[str, int] = {}
        total_rules = 0

        for analyzer in self._analyzers.values():
            dim = analyzer.dimension.value
            by_dimension[dim] = by_dimension.get(dim, 0) + 1
            total_rules += len(analyzer.rules)

        return {
            "total_analyzers": len(self._analyzers),
            "total_rules": total_rules,
            "by_dimension": by_dimension,
            "enabled": sum(1 for a in self._analyzers.values() if a.enabled),
            "disabled": sum(1 for a in self._analyzers.values() if not a.enabled),
        }


# Global registry instance
_global_registry: AnalyzerRegistry | None = None


def get_registry() -> AnalyzerRegistry:
    """
    Get the global analyzer registry.

    Returns:
        The global AnalyzerRegistry instance.
    """
    global _global_registry

    if _global_registry is None:
        _global_registry = AnalyzerRegistry()

    return _global_registry


def register_analyzer(analyzer: BaseAnalyzer) -> None:
    """
    Register an analyzer with the global registry.

    Args:
        analyzer: The analyzer to register.
    """
    get_registry().register(analyzer)


def analyzer(
    name: str | None = None,
    dimension: Dimension = Dimension.QUALITY,
    priority: int = 100,
) -> Callable[[type], type]:
    """
    Decorator to register an analyzer class.

    Example:
        >>> @analyzer(name="my-security", dimension=Dimension.SECURITY)
        ... class MySecurityAnalyzer(BaseAnalyzer):
        ...     def analyze(self, query, config=None):
        ...         return []

    Args:
        name: Optional name override.
        dimension: The dimension for this analyzer.
        priority: Execution priority.

    Returns:
        Decorator function.
    """
    def decorator(cls: type) -> type:
        # Set class attributes
        if name:
            cls.name = name  # type: ignore
        cls.dimension = dimension  # type: ignore
        cls.priority = priority  # type: ignore

        # Register instance
        instance = cls()
        get_registry().register(instance)

        return cls

    return decorator