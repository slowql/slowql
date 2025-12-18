# tests/unit/test_config.py
"""
Test configuration classes.
"""

from slowql.core.config import (
    AnalysisConfig,
    ComplianceConfig,
    Config,
    CostConfig,
    OutputConfig,
    SeverityThresholds,
)


class TestSeverityThresholds:
    def test_severity_thresholds_creation(self):
        thresholds = SeverityThresholds()
        assert thresholds.fail_on == "high"
        assert thresholds.warn_on == "medium"

    def test_severity_thresholds_custom(self):
        thresholds = SeverityThresholds(fail_on="critical", warn_on="low")
        assert thresholds.fail_on == "critical"
        assert thresholds.warn_on == "low"


class TestAnalysisConfig:
    def test_analysis_config_creation(self):
        config = AnalysisConfig()
        assert config.dialect is None
        assert config.max_query_length == 100000
        assert isinstance(config.enabled_dimensions, set)
        assert isinstance(config.disabled_rules, set)
        assert config.enabled_rules is None

    def test_analysis_config_custom(self):
        config = AnalysisConfig(
            dialect="postgres",
            max_query_length=50000,
            enabled_dimensions={"security", "performance"},
        )
        assert config.dialect == "postgres"
        assert config.max_query_length == 50000
        assert "security" in config.enabled_dimensions


class TestOutputConfig:
    def test_output_config_creation(self):
        config = OutputConfig()
        assert config.format == "text"
        assert config.color is True
        assert config.verbose is False

    def test_output_config_custom(self):
        config = OutputConfig(format="json", color=False, verbose=True)
        assert config.format == "json"
        assert config.color is False
        assert config.verbose is True


class TestComplianceConfig:
    def test_compliance_config_creation(self):
        config = ComplianceConfig()
        assert config.frameworks == set()
        assert config.strict_mode is False

    def test_compliance_config_custom(self):
        config = ComplianceConfig(frameworks={"gdpr", "hipaa"}, strict_mode=True)
        assert "gdpr" in config.frameworks
        assert "hipaa" in config.frameworks
        assert config.strict_mode is True


class TestCostConfig:
    def test_cost_config_creation(self):
        config = CostConfig()
        assert config.cloud_provider == "none"
        assert config.compute_cost_per_hour == 0.0
        assert config.storage_cost_per_gb == 0.0
        assert config.data_transfer_cost_per_gb == 0.0

    def test_cost_config_custom(self):
        config = CostConfig(
            cloud_provider="aws", compute_cost_per_hour=1.5, storage_cost_per_gb=0.1
        )
        assert config.cloud_provider == "aws"
        assert config.compute_cost_per_hour == 1.5
        assert config.storage_cost_per_gb == 0.1


class TestConfig:
    def test_config_creation(self):
        config = Config()
        assert isinstance(config.analysis, AnalysisConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.compliance, ComplianceConfig)
        assert isinstance(config.cost, CostConfig)

    def test_config_hash(self):
        config1 = Config()
        config2 = Config()
        assert config1.hash() == config2.hash()

    def test_config_with_overrides(self):
        config = Config()
        new_config = config.with_overrides(output={"format": "json"}, analysis={"dialect": "mysql"})
        assert new_config.output.format == "json"
        assert new_config.analysis.dialect == "mysql"

    def test_config_from_env(self):
        """Test loading config from environment variables."""
        result = Config.from_env()
        assert isinstance(result, Config)

    def test_config_find_and_load(self):
        """Test finding and loading config from files."""
        result = Config.find_and_load()
        assert isinstance(result, Config)

    def test_config_with_overrides_nested(self):
        """Test nested overrides."""
        config = Config()
        new_config = config.with_overrides(
            severity={"fail_on": "high", "warn_on": "low"},
            analysis={"dialect": "postgres", "max_query_length": 10000},
        )
        assert new_config.severity.fail_on == "high"
        assert new_config.severity.warn_on == "low"
        assert new_config.analysis.dialect == "postgres"
        assert new_config.analysis.max_query_length == 10000

    def test_config_hash_consistency(self):
        """Test that hash is consistent for same config."""
        config1 = Config()
        config2 = Config()
        assert config1.hash() == config2.hash()

        # Different configs should have different hashes
        config4 = config1.with_overrides(analysis={"dialect": "postgres"})
        assert config1.hash() != config4.hash()

    def test_severity_thresholds_validation(self):
        """Test severity thresholds validation."""
        # Valid values
        thresholds = SeverityThresholds(fail_on="critical", warn_on="medium")
        assert thresholds.fail_on == "critical"
        assert thresholds.warn_on == "medium"

        # Test all valid values
        for fail_val in ["critical", "high", "medium", "low", "info", "never"]:
            for warn_val in ["critical", "high", "medium", "low", "info", "never"]:
                thresholds = SeverityThresholds(fail_on=fail_val, warn_on=warn_val)
                assert thresholds.fail_on == fail_val
                assert thresholds.warn_on == warn_val

    def test_output_config_validation(self):
        """Test output config validation."""
        config = OutputConfig(
            format="json",
            color=False,
            verbose=True,
            quiet=True,
            show_fixes=False,
            show_snippets=False,
            max_issues=50,
            group_by="file",
        )
        assert config.format == "json"
        assert config.color is False
        assert config.verbose is True
        assert config.quiet is True
        assert config.show_fixes is False
        assert config.show_snippets is False
        assert config.max_issues == 50
        assert config.group_by == "file"

    def test_analysis_config_validators(self):
        """Test analysis config field validators."""
        # Test dimension conversion
        config = AnalysisConfig(enabled_dimensions=["security", "performance"])
        assert "security" in config.enabled_dimensions
        assert "performance" in config.enabled_dimensions
        assert isinstance(config.enabled_dimensions, set)

        # Test rule conversion
        config2 = AnalysisConfig(disabled_rules=["RULE-001", "RULE-002"])
        assert "RULE-001" in config2.disabled_rules
        assert isinstance(config2.disabled_rules, set)

    def test_compliance_config_frameworks(self):
        """Test compliance config frameworks handling."""
        config = ComplianceConfig(frameworks=["gdpr", "hipaa", "pci-dss"])
        assert "gdpr" in config.frameworks
        assert "hipaa" in config.frameworks
        assert "pci-dss" in config.frameworks
        assert isinstance(config.frameworks, set)

    def test_cost_config_values(self):
        """Test cost config with various values."""
        config = CostConfig(
            cloud_provider="aws",
            compute_cost_per_hour=2.5,
            storage_cost_per_gb=0.05,
            data_transfer_cost_per_gb=0.1,
        )
        assert config.cloud_provider == "aws"
        assert config.compute_cost_per_hour == 2.5
        assert config.storage_cost_per_gb == 0.05
        assert config.data_transfer_cost_per_gb == 0.1
