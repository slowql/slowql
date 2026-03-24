# tests/unit/test_severity_override.py
import pytest

from slowql.core.config import AnalysisConfig, Config
from slowql.core.engine import SlowQL
from slowql.core.models import Dimension, Issue, Location, Severity


class TestSeverityOverride:
    @pytest.fixture
    def engine(self):
        """Create an engine with default config."""
        return SlowQL(auto_discover=False)

    def test_default_severity_preserved(self, engine):
        """Verify that default severity is used when no override exists."""
        # Use a real rule ID to ensure it's not filtered out
        issue = Issue(
            rule_id="PERF-SCAN-001",
            message="Test message",
            severity=Severity.MEDIUM,
            dimension=Dimension.PERFORMANCE,
            location=Location(1, 1),
            snippet="SELECT *",
        )

        # Manually apply overrides logic (which we will implement)
        overridden = engine._apply_severity_overrides([issue])
        assert overridden[0].severity == Severity.MEDIUM

    def test_severity_downgrade(self):
        """Verify that severity can be downgraded (HIGH -> INFO)."""
        config = Config(
            analysis=AnalysisConfig(
                severity_overrides={"PERF-SCAN-001": Severity.INFO}
            )
        )
        engine = SlowQL(config=config, auto_discover=False)

        issue = Issue(
            rule_id="PERF-SCAN-001",
            message="Test message",
            severity=Severity.HIGH,
            dimension=Dimension.PERFORMANCE,
            location=Location(1, 1),
            snippet="SELECT *",
        )

        overridden = engine._apply_severity_overrides([issue])
        assert overridden[0].severity == Severity.INFO

    def test_severity_upgrade(self):
        """Verify that severity can be upgraded (INFO -> CRITICAL)."""
        config = Config(
            analysis=AnalysisConfig(
                severity_overrides={"QUAL-NULL-001": Severity.CRITICAL}
            )
        )
        engine = SlowQL(config=config, auto_discover=False)

        issue = Issue(
            rule_id="QUAL-NULL-001",
            message="Test message",
            severity=Severity.INFO,
            dimension=Dimension.QUALITY,
            location=Location(1, 1),
            snippet="id = NULL",
        )

        overridden = engine._apply_severity_overrides([issue])
        assert overridden[0].severity == Severity.CRITICAL

    def test_multiple_overrides(self):
        """Verify that multiple overrides can be applied."""
        config = Config(
            analysis=AnalysisConfig(
                severity_overrides={
                    "PERF-SCAN-001": Severity.LOW,
                    "QUAL-NULL-001": Severity.HIGH
                }
            )
        )
        engine = SlowQL(config=config, auto_discover=False)

        issues = [
            Issue(
                rule_id="PERF-SCAN-001",
                message="M1",
                severity=Severity.MEDIUM,
                dimension=Dimension.PERFORMANCE,
                location=Location(1, 1),
                snippet="S1",
            ),
            Issue(
                rule_id="QUAL-NULL-001",
                message="M2",
                severity=Severity.INFO,
                dimension=Dimension.QUALITY,
                location=Location(2, 1),
                snippet="S2",
            ),
            Issue(
                rule_id="OTHER-001",
                message="M3",
                severity=Severity.MEDIUM,
                dimension=Dimension.QUALITY,
                location=Location(3, 1),
                snippet="S3",
            )
        ]

        overridden = engine._apply_severity_overrides(issues)
        assert overridden[0].severity == Severity.LOW
        assert overridden[1].severity == Severity.HIGH
        assert overridden[2].severity == Severity.MEDIUM

    def test_config_validation(self):
        """Verify that invalid severity in config is handled (if possible via Pydantic)."""
        # This tests the AnalysisConfig validation
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AnalysisConfig(severity_overrides={"RULE-001": "invalid_severity"})

    def test_engine_integration(self):
        """Verify that overrides are applied during the full analyze() flow."""
        config = Config(
            analysis=AnalysisConfig(
                severity_overrides={"PERF-SCAN-001": Severity.CRITICAL}
            )
        )
        engine = SlowQL(config=config, auto_discover=False)

        # Mock analyzer to return a MEDIUM issue
        from unittest.mock import MagicMock
        analyzer = MagicMock()
        analyzer.dimension = Dimension.PERFORMANCE
        issue = Issue(
            rule_id="PERF-SCAN-001",
            message="Test",
            severity=Severity.MEDIUM,
            dimension=Dimension.PERFORMANCE,
            location=Location(1, 1),
            snippet="SELECT *",
        )
        analyzer.analyze.return_value = [issue]

        with MagicMock():
            engine._analyzers = [analyzer]
            engine._analyzers_loaded = True

            # Mock parse_sql
            from slowql.core.models import Query
            query = Query(raw="SELECT *", normalized="SELECT *", dialect="postgres", location=Location(1, 1))
            engine._parse_sql = MagicMock(return_value=[query])

            result = engine.analyze("SELECT *")

            assert len(result.issues) == 1
            assert result.issues[0].severity == Severity.CRITICAL
