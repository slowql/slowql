from pathlib import Path

import pytest

from slowql.core.cache import CacheManager
from slowql.core.config import Config
from slowql.core.exceptions import ConfigurationError
from slowql.migrations.discovery import MigrationDiscovery
from slowql.migrations.providers.liquibase import LiquibaseProvider
from slowql.migrations.providers.prisma import PrismaProvider


def test_cache_manager_edge_cases(tmp_path: Path) -> None:
    cache_dir = tmp_path / ".cache"
    cache = CacheManager(cache_dir)

    # Coverage for lines 20-21 (fallback version if it can't be imported)
    # We can't easily trigger the ImportError in a running test without mocking sys.modules
    # but let's test the existing paths
    assert cache.cache_dir == cache_dir
    assert cache_dir.exists()

    # Coverage for lines 34-35 (get with non-existent file)
    assert cache.get(Path("non_existent.sql"), "SELECT 1", "hash") is None

    # Coverage for lines 62-64 (clear)
    from slowql.core.models import AnalysisResult
    res = AnalysisResult(dialect="universal")
    cache.set(Path("test.sql"), "SELECT 2", "hash", res)
    cache.clear()
    assert cache.get(Path("test.sql"), "SELECT 2", "hash") is None

def test_liquibase_provider_detection(tmp_path: Path) -> None:
    provider = LiquibaseProvider()
    f = tmp_path / "changelog.sql"
    f.write_text("--liquibase formatted sql\n--changeset auth:1\nSELECT 1;")
    # detect takes a directory path
    assert provider.detect(tmp_path) is True
    # get_migrations takes a directory path
    migs = provider.get_migrations(tmp_path)
    assert len(migs) == 1

def test_prisma_provider_detection(tmp_path: Path) -> None:
    provider = PrismaProvider()
    f = tmp_path / "schema.prisma"
    f.write_text('datasource db { provider = "postgresql" }')
    assert provider.detect(tmp_path) is True

def test_breaking_change_rule_detailed() -> None:
    from sqlglot import parse_one

    from slowql.core.models import Location, Query
    from slowql.rules.migration.breaking_change import BreakingChangeRule
    from slowql.schema.models import Column, ColumnType, Schema, Table

    # Setup schema using Pydantic constructors (models are frozen)
    col1 = Column(name="id", type=ColumnType.INTEGER)
    col2 = Column(name="name", type=ColumnType.TEXT)
    table = Table(name="users", columns=(col1, col2))
    schema = Schema(tables={"users": table})

    rule = BreakingChangeRule(schema_before=schema)

    # 1. DROP TABLE
    sql_drop_table = "DROP TABLE users"
    q1 = Query(
        raw=sql_drop_table,
        normalized=sql_drop_table.upper(),
        dialect="universal",
        location=Location(1,1),
        ast=parse_one(sql_drop_table)
    )
    issues = rule.check(q1)
    assert len(issues) == 1
    assert "Dropping table 'users'" in issues[0].message

    # 2. ALTER TABLE DROP COLUMN
    sql_drop_col = "ALTER TABLE users DROP COLUMN name"
    q2 = Query(
        raw=sql_drop_col,
        normalized=sql_drop_col.upper(),
        dialect="universal",
        location=Location(1,1),
        ast=parse_one(sql_drop_col)
    )
    issues = rule.check(q2)
    assert len(issues) == 1
    assert "Dropping column 'name'" in issues[0].message

def test_prisma_provider_migrations(tmp_path: Path) -> None:
    provider = PrismaProvider()
    f = tmp_path / "schema.prisma"
    f.write_text('datasource db { provider = "postgresql" }')
    # Prisma doesn't use file system for migrations in the same way, but let's test detection
    assert provider.detect(tmp_path) is True
    # If get_migrations is called, it might return empty if no shadow db etc.
    # but we just want the line coverage of the method call.
    assert provider.get_migrations(tmp_path) == []

def test_migration_discovery_edge_cases(tmp_path: Path) -> None:
    discovery = MigrationDiscovery.default()
    # Test detection in empty dir
    assert discovery.detect_framework(tmp_path) is None

def test_lsp_server_minimal_init() -> None:
    from slowql.lsp.server import HAS_PYGLS, SlowQLLanguageServer
    if not HAS_PYGLS:
        with pytest.raises(ImportError):
            SlowQLLanguageServer()
    else:
        # If pygls present, we can init with dummy args
        server = SlowQLLanguageServer("test", "v1")
        assert server is not None

def test_config_unsupported_format(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.write_text("dummy")
    with pytest.raises(ConfigurationError) as exc:
        Config.from_file(f)
    assert "Unsupported configuration file format" in str(exc.value)

def test_config_find_and_load_no_config(tmp_path: Path) -> None:
    # Search in a fresh empty directory
    config = Config.find_and_load(tmp_path)
    # Should return defaults
    assert config.analysis.parallel is True
