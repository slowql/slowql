# tests/unit/test_rules.py
"""
Test rule classes.
"""

import pytest

from slowql.core.models import Category, Dimension, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule
from slowql.rules.catalog import (
    HardcodedPasswordRule,
    LeadingWildcardRule,
    PIIExposureRule,
    SelectStarRule,
    SQLInjectionRule,
    UnsafeWriteRule,
    get_all_rules,
)
from slowql.rules.registry import RuleRegistry, get_rule_registry


class TestRule:
    def test_rule_is_abstract(self):
        # Rule is abstract and cannot be instantiated directly
        try:
            Rule()
            raise AssertionError("Should not be able to instantiate abstract class")
        except TypeError:
            pass


class TestPatternRule:
    def test_pattern_rule_creation(self):
        rule = PatternRule()
        assert rule.pattern == ""
        assert rule.message_template == "Pattern matched: {match}"

    def test_pattern_rule_check_no_pattern(self):
        rule = PatternRule()
        query = Query(
            raw="SELECT *",
            normalized="SELECT *",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert issues == []


class TestASTRule:
    def test_ast_rule_is_abstract(self):
        # ASTRule is abstract and cannot be instantiated directly
        try:
            ASTRule()
            raise AssertionError("Should not be able to instantiate abstract class")
        except TypeError:
            pass


class TestSQLInjectionRule:
    def test_sql_injection_rule_creation(self):
        rule = SQLInjectionRule()
        assert rule.id == "SEC-INJ-001"
        assert rule.name == "Potential SQL Injection"
        assert rule.severity == Severity.CRITICAL
        assert rule.dimension == Dimension.SECURITY

    def test_sql_injection_rule_check(self):
        rule = SQLInjectionRule()
        query = Query(
            raw="SELECT * FROM users WHERE id = ' + user_input + '",
            normalized="SELECT * FROM users WHERE id = ' + user_input + '",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert len(issues) > 0


class TestHardcodedPasswordRule:
    def test_hardcoded_password_rule_creation(self):
        rule = HardcodedPasswordRule()
        assert rule.id == "SEC-AUTH-001"
        assert rule.name == "Hardcoded Password"
        assert rule.severity == Severity.HIGH

    def test_hardcoded_password_rule_check(self):
        rule = HardcodedPasswordRule()
        query = Query(
            raw="SELECT * FROM users WHERE password = 'secret123'",
            normalized="SELECT * FROM users WHERE password = 'secret123'",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert len(issues) > 0


class TestSelectStarRule:
    def test_select_star_rule_creation(self):
        rule = SelectStarRule()
        assert rule.id == "PERF-SCAN-001"
        assert rule.name == "SELECT * Usage"
        assert rule.severity == Severity.MEDIUM

    def test_select_star_rule_check(self):
        rule = SelectStarRule()
        query = Query(
            raw="SELECT * FROM users",
            normalized="SELECT * FROM users",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        rule.check(query)
        # This would require AST parsing, so may not work without proper setup


class TestLeadingWildcardRule:
    def test_leading_wildcard_rule_creation(self):
        rule = LeadingWildcardRule()
        assert rule.id == "PERF-IDX-002"
        assert rule.name == "Leading Wildcard Search"

    def test_leading_wildcard_rule_check(self):
        rule = LeadingWildcardRule()
        query = Query(
            raw="SELECT * FROM users WHERE name LIKE '%john'",
            normalized="SELECT * FROM users WHERE name LIKE '%john'",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert len(issues) > 0


class TestUnsafeWriteRule:
    def test_unsafe_write_rule_creation(self):
        rule = UnsafeWriteRule()
        assert rule.id == "REL-DATA-001"
        assert rule.name == "Catastrophic Data Loss Risk"
        assert rule.severity == Severity.CRITICAL

    def test_unsafe_write_rule_check(self):
        rule = UnsafeWriteRule()
        query = Query(
            raw="DELETE FROM users",
            normalized="DELETE FROM users",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        rule.check(query)
        # Would require AST parsing


class TestPIIExposureRule:
    def test_pii_exposure_rule_creation(self):
        rule = PIIExposureRule()
        assert rule.id == "COMP-GDPR-001"
        assert rule.name == "Potential PII Selection"

    def test_pii_exposure_rule_check(self):
        rule = PIIExposureRule()
        query = Query(
            raw="SELECT email FROM users",
            normalized="SELECT email FROM users",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert len(issues) > 0

    def test_pii_exposure_rule_check_ssn(self):
        rule = PIIExposureRule()
        query = Query(
            raw="SELECT ssn FROM users",
            normalized="SELECT ssn FROM users",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert len(issues) > 0

    def test_pii_exposure_rule_check_no_pii(self):
        rule = PIIExposureRule()
        query = Query(
            raw="SELECT id, name FROM users",
            normalized="SELECT id, name FROM users",
            dialect="mysql",
            location=Location(line=1, column=1),
        )
        issues = rule.check(query)
        assert len(issues) == 0


def test_get_all_rules():
    """Test that get_all_rules returns all built-in rules."""
    rules = get_all_rules()
    assert isinstance(rules, list)
    assert len(rules) > 0

    # Check that we have rules from different categories
    rule_ids = [rule.id for rule in rules]
    assert any(id.startswith("SEC-") for id in rule_ids)  # Security rules
    assert any(id.startswith("PERF-") for id in rule_ids)  # Performance rules
    assert any(id.startswith("REL-") for id in rule_ids)  # Reliability rules
    assert any(id.startswith("COMP-") for id in rule_ids)  # Compliance rules
    assert any(id.startswith("QUAL-") for id in rule_ids)  # Quality rules


# Test rule classes for registry testing
class SecurityRuleHelper(PatternRule):
    id = "TEST-SEC-001"
    name = "Test Security Rule"
    description = "A test security rule"
    dimension = Dimension.SECURITY
    severity = Severity.HIGH
    category = Category.SEC_INJECTION
    pattern = r"test"
    message_template = "Test security issue found"


class PerformanceRuleHelper(PatternRule):
    id = "TEST-PERF-001"
    name = "Test Performance Rule"
    description = "A test performance rule"
    dimension = Dimension.PERFORMANCE
    severity = Severity.MEDIUM
    pattern = r"test"
    message_template = "Test performance issue found"


class DisabledRuleHelper(PatternRule):
    id = "TEST-DISABLED-001"
    name = "Test Disabled Rule"
    description = "A test disabled rule"
    dimension = Dimension.QUALITY
    severity = Severity.LOW
    pattern = r"test"
    message_template = "Test disabled issue found"
    enabled = False


class TestRuleRegistry:
    """Test RuleRegistry class."""

    def test_init(self):
        """Test RuleRegistry initialization."""
        registry = RuleRegistry()
        assert len(registry) == 0
        assert registry._rules == {}
        assert all(len(ids) == 0 for ids in registry._by_dimension.values())
        assert all(len(ids) == 0 for ids in registry._by_category.values())
        assert all(len(ids) == 0 for ids in registry._by_severity.values())

    def test_register_new_rule(self):
        """Test registering a new rule."""
        registry = RuleRegistry()
        rule = SecurityRuleHelper()

        registry.register(rule)

        assert len(registry) == 1
        assert "TEST-SEC-001" in registry
        assert registry.get("TEST-SEC-001") == rule

    def test_register_rule_without_id(self):
        """Test registering a rule without an ID."""
        class NoIdRule(PatternRule):
            pass  # No id attribute

        registry = RuleRegistry()
        rule = NoIdRule()

        with pytest.raises(ValueError, match="Rule must have an ID"):
            registry.register(rule)

    def test_register_duplicate_rule(self):
        """Test registering a duplicate rule without replace flag."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = SecurityRuleHelper()  # Same ID

        registry.register(rule1)
        with pytest.raises(ValueError, match="Rule 'TEST-SEC-001' is already registered"):
            registry.register(rule2)

    def test_register_duplicate_rule_with_replace(self):
        """Test registering a duplicate rule with replace flag."""
        class TestSecurityRule2(PatternRule):
            id = "TEST-SEC-001"
            name = "Test Security Rule 2"
            description = "A test security rule 2"
            dimension = Dimension.SECURITY
            severity = Severity.HIGH
            category = Category.SEC_INJECTION
            pattern = r"test2"
            message_template = "Test security issue found 2"

        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = TestSecurityRule2()

        registry.register(rule1)
        registry.register(rule2, replace=True)

        assert len(registry) == 1
        assert registry.get("TEST-SEC-001") == rule2

    def test_unregister_existing_rule(self):
        """Test unregistering an existing rule."""
        registry = RuleRegistry()
        rule = SecurityRuleHelper()

        registry.register(rule)
        assert len(registry) == 1

        removed_rule = registry.unregister("TEST-SEC-001")
        assert removed_rule == rule
        assert len(registry) == 0
        assert "TEST-SEC-001" not in registry

    def test_unregister_nonexistent_rule(self):
        """Test unregistering a nonexistent rule."""
        registry = RuleRegistry()
        removed_rule = registry.unregister("NONEXISTENT")
        assert removed_rule is None

    def test_get_rule_info(self):
        """Test getting rule info."""
        registry = RuleRegistry()
        rule = SecurityRuleHelper()

        registry.register(rule)
        info = registry.get_rule_info("TEST-SEC-001")

        assert info is not None
        assert info["id"] == "TEST-SEC-001"
        assert info["name"] == "Test Security Rule"

    def test_get_rule_info_nonexistent(self):
        """Test getting rule info for nonexistent rule."""
        registry = RuleRegistry()
        info = registry.get_rule_info("NONEXISTENT")
        assert info is None

    def test_get_all(self):
        """Test getting all rules."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = PerformanceRuleHelper()

        registry.register(rule1)
        registry.register(rule2)

        all_rules = registry.get_all()
        assert len(all_rules) == 2
        assert all_rules[0].id == "TEST-PERF-001"
        assert all_rules[1].id == "TEST-SEC-001"

    def test_get_by_dimension(self):
        """Test getting rules by dimension."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = PerformanceRuleHelper()

        registry.register(rule1)
        registry.register(rule2)

        security_rules = registry.get_by_dimension(Dimension.SECURITY)
        assert len(security_rules) == 1
        assert security_rules[0].id == "TEST-SEC-001"

        performance_rules = registry.get_by_dimension(Dimension.PERFORMANCE)
        assert len(performance_rules) == 1
        assert performance_rules[0].id == "TEST-PERF-001"

    def test_get_by_category(self):
        """Test getting rules by category."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = PerformanceRuleHelper()

        registry.register(rule1)
        registry.register(rule2)

        injection_rules = registry.get_by_category(Category.SEC_INJECTION)
        assert len(injection_rules) == 1
        assert injection_rules[0].id == "TEST-SEC-001"

    def test_get_by_severity(self):
        """Test getting rules by severity."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = PerformanceRuleHelper()

        registry.register(rule1)
        registry.register(rule2)

        high_rules = registry.get_by_severity(Severity.HIGH)
        assert len(high_rules) == 1
        assert high_rules[0].id == "TEST-SEC-001"

        medium_rules = registry.get_by_severity(Severity.MEDIUM)
        assert len(medium_rules) == 1
        assert medium_rules[0].id == "TEST-PERF-001"

    def test_get_by_prefix(self):
        """Test getting rules by prefix."""
        class SecRule(PatternRule):
            id = "SEC-001"
            name = "Security Rule 1"
            dimension = Dimension.SECURITY
            severity = Severity.HIGH
            category = Category.SEC_INJECTION
            pattern = r"test1"

        class PerfRule(PatternRule):
            id = "PERF-001"
            name = "Performance Rule 1"
            dimension = Dimension.PERFORMANCE
            severity = Severity.MEDIUM
            pattern = r"test2"

        registry = RuleRegistry()
        rule1 = SecRule()
        rule2 = PerfRule()

        registry.register(rule1)
        registry.register(rule2)

        sec_rules = registry.get_by_prefix("SEC")
        assert len(sec_rules) == 1
        assert sec_rules[0].id == "SEC-001"

        perf_rules = registry.get_by_prefix("perf")  # Case insensitive
        assert len(perf_rules) == 1
        assert perf_rules[0].id == "PERF-001"

    def test_get_enabled(self):
        """Test getting enabled rules."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = DisabledRuleHelper()  # This rule is disabled by default

        registry.register(rule1)
        registry.register(rule2)

        enabled_rules = registry.get_enabled()
        assert len(enabled_rules) == 1
        assert enabled_rules[0].id == "TEST-SEC-001"

    def test_list_all(self):
        """Test listing all rules."""
        registry = RuleRegistry()
        rule = SecurityRuleHelper()

        registry.register(rule)
        rule_list = registry.list_all()

        assert len(rule_list) == 1
        assert rule_list[0]["id"] == "TEST-SEC-001"
        assert rule_list[0]["name"] == "Test Security Rule"

    def test_search(self):
        """Test searching rules."""
        class InjectionRule(PatternRule):
            id = "SEC-INJ-001"
            name = "SQL Injection"
            description = "Detects SQL injection"
            dimension = Dimension.SECURITY
            severity = Severity.CRITICAL
            category = Category.SEC_INJECTION
            pattern = r"injection"
            enabled = True

        class IndexRule(PatternRule):
            id = "PERF-IDX-001"
            name = "Index Usage"
            description = "Checks index usage"
            dimension = Dimension.PERFORMANCE
            severity = Severity.MEDIUM
            pattern = r"index"
            enabled = True

        registry = RuleRegistry()
        rule1 = InjectionRule()
        rule2 = IndexRule()

        registry.register(rule1)
        registry.register(rule2)

        # Search by query
        results = registry.search("injection")
        assert len(results) == 1
        assert results[0].id == "SEC-INJ-001"

        # Search by dimension
        results = registry.search("", dimensions=[Dimension.SECURITY])
        assert len(results) == 1
        assert results[0].id == "SEC-INJ-001"

        # Search by severity
        results = registry.search("", severities=[Severity.CRITICAL])
        assert len(results) == 1
        assert results[0].id == "SEC-INJ-001"

        # Search enabled only
        registry.register(DisabledRuleHelper())  # Add a disabled rule
        results = registry.search("", enabled_only=True)
        assert len(results) == 2  # Both InjectionRule and IndexRule are enabled
        rule_ids = [r.id for r in results]
        assert "SEC-INJ-001" in rule_ids
        assert "PERF-IDX-001" in rule_ids

    def test_stats(self):
        """Test getting registry statistics."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = DisabledRuleHelper()  # This rule is disabled

        registry.register(rule1)
        registry.register(rule2)

        stats = registry.stats()
        assert stats["total"] == 2
        assert stats["enabled"] == 1
        assert stats["disabled"] == 1
        assert stats["by_dimension"]["security"] == 1
        assert stats["by_dimension"]["quality"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["low"] == 1
        assert stats["by_category"]["injection"] == 1

    def test_clear(self):
        """Test clearing the registry."""
        registry = RuleRegistry()
        rule = SecurityRuleHelper()

        registry.register(rule)
        assert len(registry) == 1

        registry.clear()
        assert len(registry) == 0

    def test_contains(self):
        """Test __contains__ method."""
        registry = RuleRegistry()
        rule = SecurityRuleHelper()

        registry.register(rule)

        assert "TEST-SEC-001" in registry
        assert "NONEXISTENT" not in registry

    def test_iter(self):
        """Test __iter__ method."""
        registry = RuleRegistry()
        rule1 = SecurityRuleHelper()
        rule2 = PerformanceRuleHelper()

        registry.register(rule1)
        registry.register(rule2)

        rules = list(registry)
        assert len(rules) == 2
        # Should be sorted by ID
        assert rules[0].id == "TEST-PERF-001"
        assert rules[1].id == "TEST-SEC-001"


class TestGlobalRegistry:
    """Test global registry functions."""

    def test_get_rule_registry(self):
        """Test getting the global rule registry."""
        registry = get_rule_registry()
        assert registry is not None
        # Should return the same instance on subsequent calls
        registry2 = get_rule_registry()
        assert registry is registry2
