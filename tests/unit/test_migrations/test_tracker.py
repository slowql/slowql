import pytest
from pathlib import Path
from slowql.migrations.base import MigrationFile
from slowql.migrations.tracker import MigrationSchemaTracker
from slowql.schema.models import Schema

def test_tracker_evolution():
    tracker = MigrationSchemaTracker()
    
    migrations = [
        MigrationFile(
            version="1",
            path=Path("1.sql"),
            content="CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255));"
        ),
        MigrationFile(
            version="2",
            path=Path("2.sql"),
            content="ALTER TABLE users ADD COLUMN email VARCHAR(255);"
        ),
        MigrationFile(
            version="3",
            path=Path("3.sql"),
            content="CREATE INDEX idx_users_email ON users(email);"
        )
    ]
    
    schema = tracker.apply_migrations(migrations)
    
    assert "users" in schema.tables
    table = schema.get_table("users")
    assert table.has_column("id")
    assert table.has_column("name")
    assert table.has_column("email")
    assert len(table.indexes) == 1
    assert table.indexes[0].name == "idx_users_email"

def test_tracker_breaking_change_detection():
    tracker = MigrationSchemaTracker()
    
    migrations = [
        MigrationFile(version="1", path=Path("1.sql"), content="CREATE TABLE t1 (id INT);"),
        MigrationFile(version="2", path=Path("2.sql"), content="DROP TABLE t1;")
    ]
    
    # We want to be able to get the state at any point
    states = tracker.get_history(migrations)
    assert len(states) == 3 # Initial empty, after M1, after M2
    
    assert "t1" in states[1].tables
    assert "t1" not in states[2].tables
