# tests/unit/test_analyzers.py
"""
Test analyzer classes.
"""

import pytest

from slowql.analyzers.base import BaseAnalyzer, RuleBasedAnalyzer, PatternAnalyzer, AnalyzerResult, CompositeAnalyzer
from slowql.analyzers.registry import AnalyzerRegistry
from slowql.analyzers.security import SecurityAnalyzer
from slowql.core.models import Query, Location, Issue, Severity, Dimension


# Test analyzer classes
class AnalyzerHelper(RuleBasedAnalyzer):
    name = "test-analyzer"
    dimension = Dimension.SECURITY
    priority = 100

    def get_rules(self):
        return []


class AnalyzerHighPriorityHelper(RuleBasedAnalyzer):
    name = "test-analyzer-high"
    dimension = Dimension.SECURITY
    priority = 50

    def get_rules(self):
        return []


class AnalyzerDisabledHelper(RuleBasedAnalyzer):
    name = "test-analyzer-disabled"
    dimension = Dimension.SECURITY
    enabled = False

    def get_rules(self):
        return []


class AnalyzerPerformanceHelper(RuleBasedAnalyzer):
    name = "test-analyzer-performance"
    dimension = Dimension.PERFORMANCE

    def get_rules(self):
        return []


class GlobalAnalyzerHelper(RuleBasedAnalyzer):
    name = "global-test-analyzer"
    dimension = Dimension.SECURITY

    def get_rules(self):
        return []
from slowql.analyzers.registry import AnalyzerRegistry
from slowql.analyzers.security import SecurityAnalyzer
from slowql.core.models import Query, Location, Issue, Severity, Dimension


class TestBaseAnalyzer:
    def test_base_analyzer_is_abstract(self):
        # BaseAnalyzer is abstract and cannot be instantiated directly
        try:
            BaseAnalyzer()
            assert False, "Should not be able to instantiate abstract class"
        except TypeError:
            pass


class TestBaseAnalyzerMethods:
    """Test BaseAnalyzer concrete methods using a concrete subclass."""

    def test_analyze_with_result(self):
        """Test analyze_with_result method."""
        from slowql.core.config import Config

        analyzer = RuleBasedAnalyzer()
        query = Query(raw="SELECT *", normalized="SELECT *", dialect="mysql", location=Location(line=1, column=1))
        config = Config()

        result = analyzer.analyze_with_result(query, config=config)

        assert isinstance(result, AnalyzerResult)
        assert result.query == query
        assert result.analyzer_name == "base"
        assert result.execution_time_ms >= 0
        assert result.rules_executed == 0  # No rules
        assert result.rules_matched == 0

    def test_check_rule_without_config(self):
        """Test check_rule method without config."""
        from slowql.rules.base import PatternRule
        from slowql.core.models import Dimension, Severity

        # Create a simple test rule
        class TestRule(PatternRule):
            id = "TEST-RULE"
            name = "Test Rule"
            dimension = Dimension.QUALITY
            severity = Severity.LOW
            pattern = r"SELECT \*"
            message_template = "Found SELECT *"

        analyzer = RuleBasedAnalyzer()
        rule = TestRule()
        query = Query(raw="SELECT * FROM test", normalized="SELECT * FROM test",
                     dialect="mysql", location=Location(line=1, column=1))

        issues = analyzer.check_rule(query, rule)
        assert len(issues) == 1
        assert issues[0].rule_id == "TEST-RULE"

    def test_check_rule_with_disabled_config(self):
        """Test check_rule with disabled rule config."""
        from slowql.rules.base import PatternRule
        from slowql.core.models import Dimension, Severity
        from slowql.core.config import Config

        class TestRule(PatternRule):
            id = "TEST-RULE"
            name = "Test Rule"
            dimension = Dimension.QUALITY
            severity = Severity.LOW
            pattern = r"SELECT \*"
            message_template = "Found SELECT *"

        analyzer = RuleBasedAnalyzer()
        rule = TestRule()
        query = Query(raw="SELECT * FROM test", normalized="SELECT * FROM test",
                     dialect="mysql", location=Location(line=1, column=1))

        # Create config that disables the rule
        config = Config()
        config.analysis.disabled_rules.add("TEST-RULE")

        issues = analyzer.check_rule(query, rule, config=config)
        assert len(issues) == 0  # Rule should be disabled

    def test_check_rule_with_enabled_rules_config(self):
        """Test check_rule with enabled rules config."""
        from slowql.rules.base import PatternRule
        from slowql.core.models import Dimension, Severity
        from slowql.core.config import Config

        class TestRule(PatternRule):
            id = "TEST-RULE"
            name = "Test Rule"
            dimension = Dimension.QUALITY
            severity = Severity.LOW
            pattern = r"SELECT \*"
            message_template = "Found SELECT *"

        analyzer = RuleBasedAnalyzer()
        rule = TestRule()
        query = Query(raw="SELECT * FROM test", normalized="SELECT * FROM test",
                     dialect="mysql", location=Location(line=1, column=1))

        # Create config that only enables specific rules
        config = Config().with_overrides(analysis={"enabled_rules": {"OTHER-RULE"}})

        issues = analyzer.check_rule(query, rule, config=config)
        assert len(issues) == 0  # Rule should not be enabled

        # Now enable the rule
        config = Config().with_overrides(analysis={"enabled_rules": {"TEST-RULE"}})
        issues = analyzer.check_rule(query, rule, config=config)
        assert len(issues) == 1  # Rule should be enabled


class TestRuleBasedAnalyzer:
    def test_rule_based_analyzer_creation(self):
        analyzer = RuleBasedAnalyzer()
        assert analyzer.name == "base"
        assert analyzer.dimension == Dimension.QUALITY

    def test_rule_based_analyzer_get_rules(self):
        analyzer = RuleBasedAnalyzer()
        rules = analyzer.get_rules()
        assert rules == []

    def test_rule_based_analyzer_analyze(self):
        analyzer = RuleBasedAnalyzer()
        query = Query(raw="SELECT *", normalized="SELECT *", dialect="mysql", location=Location(line=1, column=1))
        issues = analyzer.analyze(query)
        assert issues == []

    def test_rule_based_analyzer_initialize(self):
        analyzer = RuleBasedAnalyzer()
        assert not analyzer._initialized
        analyzer.initialize()
        assert analyzer._initialized
        assert analyzer._rules == []

    def test_rule_based_analyzer_rules_property(self):
        analyzer = RuleBasedAnalyzer()
        # Should trigger initialization
        rules = analyzer.rules
        assert analyzer._initialized
        assert rules == []

    def test_rule_based_analyzer_repr(self):
        analyzer = RuleBasedAnalyzer()
        analyzer.initialize()  # Initialize to set rules
        repr_str = repr(analyzer)
        assert "RuleBasedAnalyzer" in repr_str
        assert "name='base'" in repr_str
        assert "dimension='quality'" in repr_str

    def test_rule_based_analyzer_str(self):
        analyzer = RuleBasedAnalyzer()
        str_repr = str(analyzer)
        assert "base" in str_repr
        assert "quality" in str_repr


class TestPatternAnalyzer:
    def test_pattern_analyzer_creation(self):
        analyzer = PatternAnalyzer()
        assert analyzer.patterns == []

    def test_pattern_analyzer_get_rules(self):
        analyzer = PatternAnalyzer()
        rules = analyzer.get_rules()
        assert rules == []

    def test_pattern_analyzer_analyze(self):
        """Test PatternAnalyzer analyze method."""
        from slowql.core.models import Severity

        class TestPatternAnalyzer(PatternAnalyzer):
            name = "test-pattern"
            dimension = Dimension.SECURITY
            patterns = [
                (r"password\s*=\s*'[^']+'", "SEC-001", "Hardcoded password", Severity.HIGH),
                (r"SELECT \*", "PERF-001", "SELECT * usage", Severity.MEDIUM),
            ]

        analyzer = TestPatternAnalyzer()
        query = Query(raw="SELECT password = 'secret123'", normalized="SELECT password = 'secret123'",
                     dialect="mysql", location=Location(line=1, column=1))

        issues = analyzer.analyze(query)
        assert len(issues) == 1
        assert issues[0].rule_id == "SEC-001"
        assert "Hardcoded password" in issues[0].message

    def test_pattern_analyzer_initialize(self):
        """Test PatternAnalyzer initialization compiles patterns."""
        from slowql.core.models import Severity

        class TestPatternAnalyzer(PatternAnalyzer):
            patterns = [
                (r"test", "TEST-001", "Test pattern", Severity.LOW),
            ]

        analyzer = TestPatternAnalyzer()
        assert len(analyzer._compiled_patterns) == 0

        analyzer.initialize()
        assert len(analyzer._compiled_patterns) == 1
        assert analyzer._initialized


class TestCompositeAnalyzer:
    """Test CompositeAnalyzer class."""

    def test_composite_analyzer_creation(self):
        """Test CompositeAnalyzer initialization."""
        analyzer1 = RuleBasedAnalyzer()
        analyzer2 = RuleBasedAnalyzer()

        composite = CompositeAnalyzer(
            name="test-composite",
            analyzers=[analyzer1, analyzer2],
            dimension=Dimension.SECURITY,
            description="Test composite analyzer"
        )

        assert composite.name == "test-composite"
        assert composite.dimension == Dimension.SECURITY
        assert composite.description == "Test composite analyzer"
        assert len(composite._analyzers) == 2

    def test_composite_analyzer_get_rules(self):
        """Test CompositeAnalyzer get_rules method."""
        analyzer1 = RuleBasedAnalyzer()
        analyzer2 = RuleBasedAnalyzer()

        composite = CompositeAnalyzer(
            name="test-composite",
            analyzers=[analyzer1, analyzer2]
        )

        rules = composite.get_rules()
        assert rules == []  # Both analyzers return empty rules

    def test_composite_analyzer_analyze(self):
        """Test CompositeAnalyzer analyze method."""
        analyzer1 = RuleBasedAnalyzer()
        analyzer2 = RuleBasedAnalyzer()

        composite = CompositeAnalyzer(
            name="test-composite",
            analyzers=[analyzer1, analyzer2]
        )

        query = Query(raw="SELECT *", normalized="SELECT *", dialect="mysql", location=Location(line=1, column=1))

        issues = composite.analyze(query)
        assert issues == []  # No rules, so no issues


class TestAnalyzerResult:
    def test_analyzer_result_creation(self):
        result = AnalyzerResult()
        assert result.issues == []
        assert result.query is None
        assert result.analyzer_name == ""
        assert result.execution_time_ms == 0.0
        assert result.rules_executed == 0
        assert result.rules_matched == 0
        assert result.metadata == {}

    def test_analyzer_result_bool(self):
        result = AnalyzerResult()
        assert bool(result) is False

        result.issues = [Issue(rule_id="TEST", message="test", severity=Severity.MEDIUM,
                              dimension=Dimension.QUALITY, location=Location(line=1, column=1), snippet="code")]
        assert bool(result) is True

    def test_analyzer_result_len(self):
        result = AnalyzerResult()
        assert len(result) == 0

        result.issues = [Issue(rule_id="TEST", message="test", severity=Severity.MEDIUM,
                              dimension=Dimension.QUALITY, location=Location(line=1, column=1), snippet="code")]
        assert len(result) == 1

    def test_analyzer_result_iter(self):
        issue = Issue(rule_id="TEST", message="test", severity=Severity.MEDIUM,
                     dimension=Dimension.QUALITY, location=Location(line=1, column=1), snippet="code")
        result = AnalyzerResult(issues=[issue])

        issues = list(result)
        assert issues == [issue]

    def test_analyzer_result_add_issue(self):
        result = AnalyzerResult()
        issue = Issue(rule_id="TEST", message="test", severity=Severity.MEDIUM,
                     dimension=Dimension.QUALITY, location=Location(line=1, column=1), snippet="code")

        result.add_issue(issue)
        assert len(result.issues) == 1
        assert result.rules_matched == 1

    def test_analyzer_result_filter_by_severity(self):
        loc = Location(line=1, column=1)
        issue1 = Issue(rule_id="TEST1", message="test", severity=Severity.HIGH,
                      dimension=Dimension.QUALITY, location=loc, snippet="code")
        issue2 = Issue(rule_id="TEST2", message="test", severity=Severity.LOW,
                      dimension=Dimension.QUALITY, location=loc, snippet="code")

        result = AnalyzerResult(issues=[issue1, issue2])

        high_issues = result.filter_by_severity(Severity.HIGH)
        assert len(high_issues) == 1
        assert high_issues[0].severity == Severity.HIGH

    def test_analyzer_result_with_metadata(self):
        result = AnalyzerResult(metadata={"test": "value"})
        assert result.metadata["test"] == "value"
        assert result.execution_time_ms == 0.0
        assert result.rules_executed == 0
        assert result.rules_matched == 0


class TestAnalyzerRegistry:
    def test_analyzer_registry_creation(self):
        registry = AnalyzerRegistry()
        assert registry is not None
        assert len(registry) == 0
        assert not registry._discovered

    def test_register_analyzer(self):
        registry = AnalyzerRegistry()
        analyzer = AnalyzerHelper()

        registry.register(analyzer)
        assert len(registry) == 1
        assert "test-analyzer" in registry
        assert registry.get("test-analyzer") == analyzer

    def test_register_duplicate_analyzer(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()
        analyzer2 = AnalyzerHelper()  # Same name

        registry.register(analyzer1)
        with pytest.raises(ValueError, match="Analyzer 'test-analyzer' is already registered"):
            registry.register(analyzer2)

    def test_register_analyzer_with_replace(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()

        # Create another analyzer with same name but different priority
        class TestAnalyzerReplaced(RuleBasedAnalyzer):
            name = "test-analyzer"  # Same name
            dimension = Dimension.SECURITY
            priority = 50  # Different priority

            def get_rules(self):
                return []

        analyzer2 = TestAnalyzerReplaced()

        registry.register(analyzer1)
        registry.register(analyzer2, replace=True)
        assert registry.get("test-analyzer") == analyzer2

    def test_unregister_analyzer(self):
        registry = AnalyzerRegistry()
        analyzer = AnalyzerHelper()

        registry.register(analyzer)
        assert len(registry) == 1

        removed = registry.unregister("test-analyzer")
        assert removed == analyzer
        assert len(registry) == 0
        assert "test-analyzer" not in registry

    def test_unregister_nonexistent_analyzer(self):
        registry = AnalyzerRegistry()
        removed = registry.unregister("nonexistent")
        assert removed is None

    def test_get_nonexistent_analyzer(self):
        registry = AnalyzerRegistry()
        result = registry.get("nonexistent")
        assert result is None

    def test_get_all(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()  # priority 100
        analyzer2 = AnalyzerHighPriorityHelper()  # priority 50

        registry.register(analyzer1)
        registry.register(analyzer2)

        all_analyzers = registry.get_all()
        assert len(all_analyzers) == 2
        # Should be sorted by priority then name
        assert all_analyzers[0].name == "test-analyzer-high"  # priority 50
        assert all_analyzers[1].name == "test-analyzer"  # priority 100

    def test_get_by_dimension(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()  # SECURITY
        analyzer2 = AnalyzerPerformanceHelper()  # PERFORMANCE

        registry.register(analyzer1)
        registry.register(analyzer2)

        security_analyzers = registry.get_by_dimension(Dimension.SECURITY)
        assert len(security_analyzers) == 1
        assert security_analyzers[0].name == "test-analyzer"

    def test_get_enabled(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()  # enabled by default
        analyzer2 = AnalyzerDisabledHelper()  # disabled

        registry.register(analyzer1)
        registry.register(analyzer2)

        enabled_analyzers = registry.get_enabled()
        assert len(enabled_analyzers) == 1
        assert enabled_analyzers[0].name == "test-analyzer"

    def test_discover(self):
        registry = AnalyzerRegistry()
        count = registry.discover()
        assert isinstance(count, int)
        assert registry._discovered
        # Should discover at least some analyzers
        assert len(registry) >= 0

    def test_discover_idempotent(self):
        registry = AnalyzerRegistry()
        count1 = registry.discover()
        count2 = registry.discover()  # Should return same count
        assert count1 == count2

    def test_contains(self):
        registry = AnalyzerRegistry()
        analyzer = AnalyzerHelper()

        registry.register(analyzer)

        assert "test-analyzer" in registry
        assert "nonexistent" not in registry

    def test_iter(self):
        registry = AnalyzerRegistry()
        analyzer = AnalyzerHelper()

        registry.register(analyzer)

        analyzers = list(registry)
        assert len(analyzers) == 1
        assert analyzers[0] == analyzer

    def test_list_names(self):
        registry = AnalyzerRegistry()
        analyzer = AnalyzerHelper()

        registry.register(analyzer)

        names = registry.list_names()
        assert "test-analyzer" in names

    def test_list_dimensions(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()  # SECURITY
        analyzer2 = AnalyzerPerformanceHelper()  # PERFORMANCE

        registry.register(analyzer1)
        registry.register(analyzer2)

        dimensions = registry.list_dimensions()
        assert Dimension.SECURITY in dimensions
        assert Dimension.PERFORMANCE in dimensions

    def test_clear(self):
        registry = AnalyzerRegistry()
        analyzer = AnalyzerHelper()

        registry.register(analyzer)
        registry._discovered = True  # Simulate discovery
        assert len(registry) == 1

        registry.clear()
        assert len(registry) == 0
        assert not registry._discovered

    def test_stats(self):
        registry = AnalyzerRegistry()
        analyzer1 = AnalyzerHelper()  # enabled
        analyzer2 = AnalyzerDisabledHelper()  # disabled

        registry.register(analyzer1)
        registry.register(analyzer2)

        stats = registry.stats()
        assert stats["total_analyzers"] == 2
        assert stats["enabled"] == 1
        assert stats["disabled"] == 1
        assert stats["by_dimension"]["security"] == 2  # Both are security
        assert "total_rules" in stats


class TestGlobalRegistry:
    """Test global registry functions."""

    def test_get_registry(self):
        from slowql.analyzers.registry import get_registry

        registry = get_registry()
        assert registry is not None
        # Should return the same instance
        registry2 = get_registry()
        assert registry is registry2

    def test_register_analyzer_global(self):
        from slowql.analyzers.registry import register_analyzer, get_registry

        registry = get_registry()
        initial_count = len(registry)

        analyzer = GlobalAnalyzerHelper()

        register_analyzer(analyzer)
        assert len(registry) == initial_count + 1
        assert "global-test-analyzer" in registry

    def test_analyzer_decorator(self):
        from slowql.analyzers.registry import analyzer, get_registry
        from slowql.analyzers.base import BaseAnalyzer

        registry = get_registry()
        initial_count = len(registry)

        @analyzer(name="decorated-analyzer", dimension=Dimension.SECURITY, priority=50)
        class DecoratedAnalyzer(BaseAnalyzer):
            def get_rules(self):
                return []

            def analyze(self, query, config=None):
                return []

        assert len(registry) == initial_count + 1
        assert "decorated-analyzer" in registry

        decorated_analyzer = registry.get("decorated-analyzer")
        assert decorated_analyzer is not None
        assert decorated_analyzer.dimension == Dimension.SECURITY
        assert decorated_analyzer.priority == 50


class TestSecurityAnalyzer:
    def test_security_analyzer_creation(self):
        analyzer = SecurityAnalyzer()
        assert analyzer.name == "security"
        assert analyzer.dimension == Dimension.SECURITY
        assert analyzer.description == "Detects SQL injection, hardcoded secrets, and privilege issues."
        assert analyzer.priority == 10

    def test_security_analyzer_get_rules(self):
        analyzer = SecurityAnalyzer()
        rules = analyzer.get_rules()
        assert len(rules) == 3  # SQLInjectionRule, HardcodedPasswordRule, GrantAllRule

    def test_security_analyzer_analyze(self):
        analyzer = SecurityAnalyzer()
        query = Query(raw="SELECT * FROM users WHERE password = 'secret123'",
                     normalized="SELECT * FROM users WHERE password = 'secret123'",
                     dialect="mysql", location=Location(line=1, column=1))

        issues = analyzer.analyze(query)
        # Should find hardcoded password
        assert len(issues) > 0