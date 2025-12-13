# slowql/src/slowql/rules/registry.py
"""
Rule registry for SlowQL.

This module provides a registry for managing detection rules.
Rules can be looked up by ID, filtered by dimension/category,
and enumerated for documentation generation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterator

from slowql.core.models import Category, Dimension, Severity

if TYPE_CHECKING:
    from slowql.rules.base import Rule


class RuleRegistry:
    """
    Registry for managing detection rules.

    The registry allows:
    - Registration and lookup of rules by ID
    - Filtering rules by dimension, category, or severity
    - Enumeration for documentation generation
    - Statistics about available rules

    Example:
        >>> registry = RuleRegistry()
        >>> registry.register(SelectStarRule())
        >>> registry.register(SqlInjectionRule())
        >>>
        >>> # Look up a rule
        >>> rule = registry.get("PERF-SCAN-001")
        >>>
        >>> # Get all security rules
        >>> security_rules = registry.get_by_dimension(Dimension.SECURITY)
        >>>
        >>> # Get critical rules only
        >>> critical = registry.get_by_severity(Severity.CRITICAL)
    """

    def __init__(self) -> None:
        """Initialize the registry."""
        self._rules: dict[str, Rule] = {}
        self._by_dimension: dict[Dimension, list[str]] = {d: [] for d in Dimension}
        self._by_category: dict[Category, list[str]] = {c: [] for c in Category}
        self._by_severity: dict[Severity, list[str]] = {s: [] for s in Severity}

    def register(self, rule: Rule, *, replace: bool = False) -> None:
        """
        Register a rule.

        Args:
            rule: The rule to register.
            replace: If True, replace existing rule with same ID.

        Raises:
            ValueError: If rule with same ID exists and replace=False.
        """
        rule_id = rule.id

        if not rule_id:
            raise ValueError("Rule must have an ID")

        if rule_id in self._rules and not replace:
            raise ValueError(
                f"Rule '{rule_id}' is already registered. "
                f"Use replace=True to override."
            )

        # Remove from indices if replacing
        if rule_id in self._rules:
            self._remove_from_indices(rule_id)

        # Add to main registry
        self._rules[rule_id] = rule

        # Add to indices
        self._by_dimension[rule.dimension].append(rule_id)
        if rule.category:
            self._by_category[rule.category].append(rule_id)
        self._by_severity[rule.severity].append(rule_id)

    def _remove_from_indices(self, rule_id: str) -> None:
        """Remove a rule from all indices."""
        rule = self._rules.get(rule_id)
        if not rule:
            return

        if rule_id in self._by_dimension[rule.dimension]:
            self._by_dimension[rule.dimension].remove(rule_id)
        if rule.category and rule_id in self._by_category[rule.category]:
            self._by_category[rule.category].remove(rule_id)
        if rule_id in self._by_severity[rule.severity]:
            self._by_severity[rule.severity].remove(rule_id)

    def unregister(self, rule_id: str) -> Rule | None:
        """
        Unregister a rule by ID.

        Args:
            rule_id: The rule ID to unregister.

        Returns:
            The removed rule, or None if not found.
        """
        if rule_id not in self._rules:
            return None

        self._remove_from_indices(rule_id)
        return self._rules.pop(rule_id)

    def get(self, rule_id: str) -> Rule | None:
        """
        Get a rule by ID.

        Args:
            rule_id: The rule ID.

        Returns:
            The rule, or None if not found.
        """
        return self._rules.get(rule_id)

    def get_rule_info(self, rule_id: str) -> dict[str, Any] | None:
        """
        Get information about a rule.

        Args:
            rule_id: The rule ID.

        Returns:
            Dictionary with rule information, or None if not found.
        """
        rule = self.get(rule_id)
        if rule is None:
            return None
        return rule.metadata.to_dict()

    def get_all(self) -> list[Rule]:
        """
        Get all registered rules.

        Returns:
            List of all rules sorted by ID.
        """
        return [self._rules[k] for k in sorted(self._rules.keys())]

    def get_by_dimension(self, dimension: Dimension) -> list[Rule]:
        """
        Get rules for a specific dimension.

        Args:
            dimension: The dimension to filter by.

        Returns:
            List of matching rules sorted by ID.
        """
        rule_ids = sorted(self._by_dimension.get(dimension, []))
        return [self._rules[rid] for rid in rule_ids]

    def get_by_category(self, category: Category) -> list[Rule]:
        """
        Get rules for a specific category.

        Args:
            category: The category to filter by.

        Returns:
            List of matching rules sorted by ID.
        """
        rule_ids = sorted(self._by_category.get(category, []))
        return [self._rules[rid] for rid in rule_ids]

    def get_by_severity(self, severity: Severity) -> list[Rule]:
        """
        Get rules with a specific severity.

        Args:
            severity: The severity to filter by.

        Returns:
            List of matching rules sorted by ID.
        """
        rule_ids = sorted(self._by_severity.get(severity, []))
        return [self._rules[rid] for rid in rule_ids]

    def get_by_prefix(self, prefix: str) -> list[Rule]:
        """
        Get rules with IDs starting with a prefix.

        Args:
            prefix: The ID prefix (e.g., "SEC-INJ").

        Returns:
            List of matching rules sorted by ID.
        """
        prefix_upper = prefix.upper()
        matching = [
            rule_id for rule_id in self._rules
            if rule_id.upper().startswith(prefix_upper)
        ]
        return [self._rules[rid] for rid in sorted(matching)]

    def get_enabled(self) -> list[Rule]:
        """
        Get all enabled rules.

        Returns:
            List of enabled rules sorted by ID.
        """
        return [
            rule for rule in self.get_all()
            if rule.enabled
        ]

    def list_all(self) -> list[dict[str, Any]]:
        """
        List all rules with their metadata.

        Returns:
            List of dictionaries with rule information.
        """
        return [rule.metadata.to_dict() for rule in self.get_all()]

    def search(
        self,
        query: str,
        *,
        dimensions: list[Dimension] | None = None,
        severities: list[Severity] | None = None,
        enabled_only: bool = False,
    ) -> list[Rule]:
        """
        Search for rules matching criteria.

        Args:
            query: Text to search in ID, name, description.
            dimensions: Optional list of dimensions to filter.
            severities: Optional list of severities to filter.
            enabled_only: If True, only return enabled rules.

        Returns:
            List of matching rules.
        """
        query_lower = query.lower()
        results = []

        for rule in self._rules.values():
            # Check enabled filter
            if enabled_only and not rule.enabled:
                continue

            # Check dimension filter
            if dimensions and rule.dimension not in dimensions:
                continue

            # Check severity filter
            if severities and rule.severity not in severities:
                continue

            # Check text search
            if query_lower:
                searchable = f"{rule.id} {rule.name} {rule.description}".lower()
                if query_lower not in searchable:
                    continue

            results.append(rule)

        return sorted(results, key=lambda r: r.id)

    def stats(self) -> dict[str, Any]:
        """
        Get statistics about registered rules.

        Returns:
            Dictionary with rule statistics.
        """
        return {
            "total": len(self._rules),
            "enabled": sum(1 for r in self._rules.values() if r.enabled),
            "disabled": sum(1 for r in self._rules.values() if not r.enabled),
            "by_dimension": {
                d.value: len(ids) for d, ids in self._by_dimension.items() if ids
            },
            "by_severity": {
                s.value: len(ids) for s, ids in self._by_severity.items() if ids
            },
            "by_category": {
                c.value: len(ids) for c, ids in self._by_category.items() if ids
            },
        }

    def __len__(self) -> int:
        """Return number of registered rules."""
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        """Iterate over all rules."""
        return iter(self.get_all())

    def __contains__(self, rule_id: str) -> bool:
        """Check if a rule is registered."""
        return rule_id in self._rules

    def clear(self) -> None:
        """Clear all registered rules."""
        self._rules.clear()
        self._by_dimension = {d: [] for d in Dimension}
        self._by_category = {c: [] for c in Category}
        self._by_severity = {s: [] for s in Severity}


# Global registry instance
_global_rule_registry: RuleRegistry | None = None


def get_rule_registry() -> RuleRegistry:
    """
    Get the global rule registry.

    Returns:
        The global RuleRegistry instance.
    """
    global _global_rule_registry

    if _global_rule_registry is None:
        _global_rule_registry = RuleRegistry()
        _load_builtin_rules(_global_rule_registry)

    return _global_rule_registry


def _load_builtin_rules(registry: RuleRegistry) -> None:
    """Load all built-in rules into the registry."""
    try:
        from slowql.rules.catalog import get_all_rules
        for rule in get_all_rules():
            registry.register(rule)
    except ImportError:
        # Catalog not yet implemented or available
        pass


# Export public API
__all__ = [
    "RuleRegistry",
    "get_rule_registry",
]
