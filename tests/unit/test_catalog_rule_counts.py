"""Regression tests for rule count consistency.

These tests ensure that the catalog, analyzer docstrings, and documentation
stay in sync as rules are added or removed. If a test fails, update all
stale references before merging.
"""
from __future__ import annotations

from slowql.rules.catalog import get_all_rules, get_rules_by_dimension

# ── Source of truth: catalog.py ──────────────────────────────────────────

EXPECTED_TOTAL = 283

EXPECTED_PER_DIMENSION: dict[str, int] = {
    "security": 61,
    "performance": 73,
    "quality": 52,
    "cost": 33,
    "compliance": 18,
    "reliability": 44,
    "migration": 1,
    "schema": 1,
}

EXPECTED_DIALECT_AWARE = 108
EXPECTED_UNIVERSAL = 175


# ── Tests ────────────────────────────────────────────────────────────────


class TestCatalogTotalCount:
    """Verify the total number of rules in the catalog."""

    def test_total_rule_count(self) -> None:
        rules = get_all_rules()
        assert len(rules) == EXPECTED_TOTAL, (
            f"Expected {EXPECTED_TOTAL} rules, got {len(rules)}. "
            "Update EXPECTED_TOTAL and all documentation if rules were added/removed."
        )

    def test_all_ids_unique(self) -> None:
        rules = get_all_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), (
            f"Duplicate rule IDs found: "
            f"{sorted(x for x in set(ids) if ids.count(x) > 1)}"
        )


class TestDimensionCounts:
    """Verify per-dimension rule counts match expectations."""

    def test_dimension_counts(self) -> None:
        for dimension, expected in EXPECTED_PER_DIMENSION.items():
            actual = len(get_rules_by_dimension(dimension))
            assert actual == expected, (
                f"Dimension '{dimension}': expected {expected} rules, got {actual}. "
                "Update EXPECTED_PER_DIMENSION and analyzer docstrings."
            )

    def test_dimension_sum_equals_total(self) -> None:
        total = sum(EXPECTED_PER_DIMENSION.values())
        assert total == EXPECTED_TOTAL, (
            f"Sum of per-dimension counts ({total}) != EXPECTED_TOTAL ({EXPECTED_TOTAL}). "
            "Dimension counts are out of sync."
        )


class TestDialectSplit:
    """Verify dialect-aware vs universal rule counts."""

    def test_dialect_aware_count(self) -> None:
        rules = get_all_rules()
        dialect_aware = sum(1 for r in rules if getattr(r, "dialects", None))
        assert dialect_aware == EXPECTED_DIALECT_AWARE, (
            f"Expected {EXPECTED_DIALECT_AWARE} dialect-aware rules, got {dialect_aware}."
        )

    def test_universal_count(self) -> None:
        rules = get_all_rules()
        universal = sum(1 for r in rules if not getattr(r, "dialects", None))
        assert universal == EXPECTED_UNIVERSAL, (
            f"Expected {EXPECTED_UNIVERSAL} universal rules, got {universal}."
        )

    def test_dialect_split_sums_to_total(self) -> None:
        assert EXPECTED_DIALECT_AWARE + EXPECTED_UNIVERSAL == EXPECTED_TOTAL
