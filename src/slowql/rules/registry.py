# slowql/src/slowql/rules/registry.py
"""
Rule registry for SlowQL.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from slowql.core.models import Category, Dimension, Severity

if TYPE_CHECKING:
    from slowql.rules.base import Rule

if TYPE_CHECKING:
    from collections.abc import Iterator

    from slowql.rules.base import Rule

class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._by_dimension: dict[Dimension, list[str]] = {d: [] for d in Dimension}
        self._by_category: dict[Category, list[str]] = {c: [] for c in Category}
        self._by_severity: dict[Severity, list[str]] = {s: [] for s in Severity}

    def register(self, rule: Rule, *, replace: bool = False) -> None:
        rule_id = rule.id
        if not rule_id:
            raise ValueError("Rule must have an ID")
        if rule_id in self._rules and not replace:
            raise ValueError(f"Rule '{rule_id}' is already registered.")
        if rule_id in self._rules:
            self._remove_from_indices(rule_id)
        self._rules[rule_id] = rule
        self._by_dimension[rule.dimension].append(rule_id)
        if rule.category:
            self._by_category[rule.category].append(rule_id)
        self._by_severity[rule.severity].append(rule_id)

    def _remove_from_indices(self, rule_id: str) -> None:
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
        if rule_id not in self._rules:
            return None
        self._remove_from_indices(rule_id)
        return self._rules.pop(rule_id)

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def get_rule_info(self, rule_id: str) -> dict[str, Any] | None:
        rule = self.get(rule_id)
        if rule is None:
            return None
        return rule.metadata.to_dict()

    def get_all(self) -> list[Rule]:
        return [self._rules[k] for k in sorted(self._rules.keys())]

    def get_by_dimension(self, dimension: Dimension) -> list[Rule]:
        rule_ids = sorted(self._by_dimension.get(dimension, []))
        return [self._rules[rid] for rid in rule_ids]

    def get_by_category(self, category: Category) -> list[Rule]:
        rule_ids = sorted(self._by_category.get(category, []))
        return [self._rules[rid] for rid in rule_ids]

    def get_by_severity(self, severity: Severity) -> list[Rule]:
        rule_ids = sorted(self._by_severity.get(severity, []))
        return [self._rules[rid] for rid in rule_ids]

    def get_by_prefix(self, prefix: str) -> list[Rule]:
        prefix_upper = prefix.upper()
        matching = [rule_id for rule_id in self._rules if rule_id.upper().startswith(prefix_upper)]
        return [self._rules[rid] for rid in sorted(matching)]

    def get_enabled(self) -> list[Rule]:
        return [rule for rule in self.get_all() if rule.enabled]

    def list_all(self) -> list[dict[str, Any]]:
        return [rule.metadata.to_dict() for rule in self.get_all()]

    def search(
        self,
        query: str,
        *,
        dimensions: list[Dimension] | None = None,
        severities: list[Severity] | None = None,
        enabled_only: bool = False,
    ) -> list[Rule]:
        query_lower = query.lower()
        results = []
        for rule in self._rules.values():
            if enabled_only and not rule.enabled:
                continue
            if dimensions and rule.dimension not in dimensions:
                continue
            if severities and rule.severity not in severities:
                continue
            if query_lower:
                searchable = f"{rule.id} {rule.name} {rule.description}".lower()
                if query_lower not in searchable:
                    continue
            results.append(rule)
        return sorted(results, key=lambda r: r.id)

    def stats(self) -> dict[str, Any]:
        return {
            "total": len(self._rules),
            "enabled": sum(1 for r in self._rules.values() if r.enabled),
            "disabled": sum(1 for r in self._rules.values() if not r.enabled),
            "by_dimension": {d.value: len(ids) for d, ids in self._by_dimension.items() if ids},
            "by_severity": {s.value: len(ids) for s, ids in self._by_severity.items() if ids},
            "by_category": {c.value: len(ids) for c, ids in self._by_category.items() if ids},
        }

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.get_all())

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def clear(self) -> None:
        self._rules.clear()
        self._by_dimension = {d: [] for d in Dimension}
        self._by_category = {c: [] for c in Category}
        self._by_severity = {s: [] for s in Severity}


_global_rule_registry: list[RuleRegistry] = []


def get_rule_registry() -> RuleRegistry:
    """Get the global, singleton instance of the RuleRegistry."""
    if not _global_rule_registry:
        registry = RuleRegistry()
        _load_builtin_rules(registry)
        _global_rule_registry.append(registry)
    return _global_rule_registry[0]


def _load_builtin_rules(registry: RuleRegistry) -> None:
    from slowql.rules.catalog import get_all_rules  # noqa: PLC0415

    try:
        for rule in get_all_rules():
            registry.register(rule)
    except ImportError:
        pass


__all__ = ["RuleRegistry", "get_rule_registry"]
