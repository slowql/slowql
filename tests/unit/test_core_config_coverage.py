import os
from unittest.mock import MagicMock, patch

import pytest

from slowql.core.config import AnalysisConfig, Config
from slowql.core.exceptions import ConfigurationError


class TestConfigCoverage:
    def test_from_file_formats(self, tmp_path):
        # TOML
        toml_path = tmp_path / "config.toml"
        toml_path.write_text('[analysis]\ndialect = "postgres"')
        cfg = Config.from_file(toml_path)
        assert cfg.analysis.dialect == "postgres"

        # JSON
        json_path = tmp_path / "config.json"
        json_path.write_text('{"analysis": {"dialect": "mysql"}}')
        cfg = Config.from_file(json_path)
        assert cfg.analysis.dialect == "mysql"

        # YAML
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("analysis:\n  dialect: sqlite")

        # Mock the yaml import to avoid ModuleNotFoundError in test env
        mock_yaml = MagicMock()
        mock_yaml.safe_load.return_value = {"analysis": {"dialect": "sqlite"}}
        with patch("slowql.core.config.yaml", mock_yaml):
            cfg = Config.from_file(yaml_path)
            assert cfg.analysis.dialect == "sqlite"
            mock_yaml.safe_load.assert_called_once_with(
                "analysis:\n  dialect: sqlite"
            )

    def test_from_file_errors(self, tmp_path):
        # Missing
        with pytest.raises(ConfigurationError) as exc:
            Config.from_file("nonexistent.toml")
        assert "not found" in str(exc.value)

        # Invalid format
        txt_path = tmp_path / "config.txt"
        txt_path.write_text("sdsd")
        with pytest.raises(ConfigurationError) as exc:
            Config.from_file(txt_path)
        assert "Unsupported configuration" in str(exc.value)

        # Parse error
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{")
        with pytest.raises(ConfigurationError) as exc:
            Config.from_file(bad_json)
        assert "Failed to parse" in str(exc.value)

    def test_from_env(self):
        env = {
            "SLOWQL_ANALYSIS__DIALECT": "oracle",
            "SLOWQL_OUTPUT__COLOR": "false",
            "SLOWQL_ANALYSIS__MAX_QUERY_LENGTH": "500",
            "SLOWQL_ANALYSIS__TIMEOUT_SECONDS": "1.5",
            "SLOWQL_ANALYSIS__ENABLED_DIMENSIONS": "security,performance",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = Config.from_env()
            assert cfg.analysis.dialect == "oracle"
            assert cfg.output.color is False
            assert cfg.analysis.max_query_length == 500
            assert cfg.analysis.timeout_seconds == 1.5
            assert "security" in cfg.analysis.enabled_dimensions
            assert "performance" in cfg.analysis.enabled_dimensions

    def test_parse_env_value(self):
        # Test static method logic
        assert Config._parse_env_value("true") is True
        assert Config._parse_env_value("ON") is True
        assert Config._parse_env_value("1") is True
        assert Config._parse_env_value("False") is False
        assert Config._parse_env_value("0") is False
        assert Config._parse_env_value("123") == 123
        assert Config._parse_env_value("12.3") == 12.3
        assert Config._parse_env_value("a,b") == ["a", "b"]
        assert Config._parse_env_value("foo") == "foo"

    def test_find_and_load_traversal(self, tmp_path):
        # Create structure: /tmp/root/subdir
        root = tmp_path / "root"
        subdir = root / "subdir"
        subdir.mkdir(parents=True)

        # Scenario 1: Config in root, called from subdir
        (root / "slowql.toml").write_text('[analysis]\ndialect = "root"')
        cfg = Config.find_and_load(start_path=subdir)
        assert cfg.analysis.dialect == "root"

        # Scenario 2: Config in subdir
        (subdir / "slowql.json").write_text('{"analysis": {"dialect": "subdir"}}')
        cfg = Config.find_and_load(start_path=subdir)
        assert cfg.analysis.dialect == "subdir"  # Subdir takes precedence

        # Scenario 3: pyproject.toml
        (subdir / "slowql.json").unlink()
        (root / "slowql.toml").unlink()
        (root / "pyproject.toml").write_text('[tool.slowql.analysis]\ndialect = "pyp"')
        cfg = Config.find_and_load(start_path=subdir)
        assert cfg.analysis.dialect == "pyp"

        # Scenario 4: No config found
        (root / "pyproject.toml").unlink()
        cfg = Config.find_and_load(start_path=subdir)
        # Should return defaults/env
        assert cfg.analysis.dialect is None  # Default

    def test_with_overrides(self):
        cfg = Config()
        new_cfg = cfg.with_overrides(output={"format": "json"}, analysis={"dialect": "mysql"})
        assert new_cfg.output.format == "json"
        assert new_cfg.analysis.dialect == "mysql"
        # Original unchanged
        assert cfg.output.format == "text"

    def test_hash(self):
        cfg1 = Config()
        cfg2 = Config()
        assert cfg1.hash() == cfg2.hash()

        cfg3 = cfg1.with_overrides(analysis={"dialect": "postgres"})
        assert cfg1.hash() != cfg3.hash()

    def test_validators(self):
        # Validate logic for list->set
        data = {"enabled_dimensions": ["security"], "disabled_rules": ["R1", "R2"]}
        model = AnalysisConfig(**data)
        assert isinstance(model.enabled_dimensions, set)
        assert "security" in model.enabled_dimensions
        assert isinstance(model.disabled_rules, set)
