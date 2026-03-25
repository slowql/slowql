import pytest
from pathlib import Path
from slowql.migrations.providers.django import DjangoProvider

def test_django_detection(tmp_path):
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "__init__.py").touch()
    provider = DjangoProvider()
    assert provider.detect(tmp_path) is True

def test_django_extraction(tmp_path):
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir(exist_ok=True)
    (migrations_dir / "__init__.py").touch()
    
    migration_content = """
class Migration(migrations.Migration):
    dependencies = [('users', '0001_initial')]
    operations = [
        migrations.CreateModel(name='Profile', fields=[('id', models.AutoField())]),
        migrations.AddField(model_name='users', name='bio', field=models.TextField()),
        migrations.RemoveField(model_name='users', name='old_bio'),
        migrations.DeleteModel(name='OldModel'),
    ]
"""
    (migrations_dir / "0002_profile.py").write_text(migration_content)
    
    provider = DjangoProvider()
    migrations = provider.get_migrations(tmp_path)
    
    assert len(migrations) == 1
    m = migrations[0]
    assert m.version == "0002"
    assert "CREATE TABLE profile" in m.content
    assert "ALTER TABLE users ADD COLUMN bio" in m.content
    assert "ALTER TABLE users DROP COLUMN old_bio" in m.content
    assert "DROP TABLE oldmodel" in m.content
