import pytest
from pathlib import Path
from slowql.migrations.providers.alembic import AlembicProvider
from slowql.migrations.base import MigrationFile

def test_alembic_detection(tmp_path):
    (tmp_path / "versions").mkdir()
    provider = AlembicProvider()
    assert provider.detect(tmp_path) is True

def test_alembic_extaction(tmp_path):
    versions_dir = tmp_path / "versions"
    versions_dir.mkdir()
    
    import textwrap
    migration_content = textwrap.dedent("""
        revision = '1234'
        down_revision = None

        def upgrade():
            op.create_table('users', op.column('id', op.Integer))
            op.add_column('users', op.column('email', op.String))
            op.drop_column('users', 'old_field')
            op.drop_table('old_table')
    """).strip()
    migration_file = versions_dir / "1234_init.py"
    migration_file.write_text(migration_content)
    
    provider = AlembicProvider()
    migrations = provider.get_migrations(tmp_path)
    
    assert len(migrations) == 1
    m = migrations[0]
    assert m.version == "1234"
    assert "CREATE TABLE users" in m.content
    assert "ALTER TABLE users ADD COLUMN email" in m.content
    assert "ALTER TABLE users DROP COLUMN old_field" in m.content
    assert "DROP TABLE old_table" in m.content
