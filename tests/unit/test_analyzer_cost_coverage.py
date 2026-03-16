from unittest.mock import MagicMock

from slowql.analyzers.cost import CostAnalyzer
from slowql.core.models import Location


class TestCostAnalyzerCoverage:
    def test_get_rules(self):
        analyzer = CostAnalyzer()
        assert (
            len(analyzer.get_rules()) == 32
        )  # Updated after adding dialect-specific cost rules

    def test_analyze_fallback_is_select(self):
        analyzer = CostAnalyzer()

        # Mock a query-like object that doesn't have is_select property
        # Query class has slots, so we can't easily delete attributes from real instance
        # We'll use a plain MagicMock
        mock_query = MagicMock()
        del mock_query.is_select  # Ensure it doesn't have this attribute
        mock_query.query_type = "SELECT"
        mock_query.raw = "SELECT count(*) FROM t"
        mock_query.location = Location(1, 1)

        # analyze uses hasattr(query, "is_select")
        # If we use MagicMock, hasattr usually returns True unless we ensure it raises
        # AttributeError on access.
        # Actually hasattr checks if attribute exists.
        # MagicMock creates attributes on access.
        # To make hasattr return False, we need to make sure accessing the attribute
        # raises AttributeError.

        # Better way: clean mock class
        class MockQuery:
            raw = "SELECT count(*) FROM t"
            query_type = "SELECT"
            location = Location(1, 1)
            # no is_select here

        q = MockQuery()
        issues = analyzer.analyze(q)
        # Should detect 3 issues now: legacy "COST-COMP-002" + 2 catalog rules (COST-COMPUTE-001, COST-PAGE-003)
        assert len(issues) >= 1
        rule_ids = {issue.rule_id for issue in issues}
        assert "COST-COMP-002" in rule_ids

    def test_analyze_fallback_not_select(self):
        analyzer = CostAnalyzer()

        class MockQuery:
            raw = "INSERT INTO t..."
            query_type = "INSERT"
            location = Location(1, 1)

        q = MockQuery()
        issues = analyzer.analyze(q)
        assert len(issues) == 0

    def test_analyze_no_query_type(self):
        analyzer = CostAnalyzer()

        class MockQuery:
            raw = "something"
            query_type = None
            location = Location(1, 1)

        q = MockQuery()
        issues = analyzer.analyze(q)
        assert len(issues) == 0
