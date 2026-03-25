import pytest
from pathlib import Path
from slowql.migrations.base import MigrationProvider, MigrationFile
from slowql.migrations.discovery import MigrationDiscovery

class MockProvider(MigrationProvider):
    def detect(self, path: Path) -> bool:
        return (path / "mock.migrations").exists()

    def get_migrations(self, path: Path) -> list[MigrationFile]:
        if not self.detect(path):
            return []
        return [
            MigrationFile(version="1", path=path / "1.sql", content="CREATE TABLE t1 (id INT);"),
            MigrationFile(version="2", path=path / "2.sql", content="ALTER TABLE t1 ADD COLUMN name TEXT;"),
        ]

def test_migration_file_model():
    mf = MigrationFile(version="1", path=Path("1.sql"), content="SELECT 1")
    assert mf.version == "1"
    assert mf.content == "SELECT 1"

def test_discovery_registry():
    discovery = MigrationDiscovery()
    discovery.register("mock", MockProvider())
    
    # Test detection failing
    tmp_path = Path("/tmp/slowql_test_empty")
    tmp_path.mkdir(exist_ok=True)
    assert discovery.detect_framework(tmp_path) is None
    
    # Test detection succeeding
    mock_path = Path("/tmp/slowql_test_mock")
    mock_path.mkdir(exist_ok=True)
    (mock_path / "mock.migrations").touch()
    
    assert discovery.detect_framework(mock_path) == "mock"
    
    migrations = discovery.get_migrations(mock_path)
    assert len(migrations) == 2
    assert migrations[0].version == "1"
    assert migrations[1].version == "2"
