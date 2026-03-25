import textwrap

from slowql.migrations.providers.django import DjangoProvider


def test_django_detection(tmp_path):
    (tmp_path / "myapp").mkdir()
    (tmp_path / "myapp" / "migrations").mkdir()
    provider = DjangoProvider()
    assert provider.detect(tmp_path) is True

def test_django_extraction(tmp_path):
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()
    migrations_dir = app_dir / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "__init__.py").write_text("")

    migration_content = textwrap.dedent("""
        from django.db import migrations, models

        class Migration(migrations.Migration):
            dependencies = [
                ('otherapp', '0001_initial'),
            ]
            operations = [
                migrations.CreateModel(
                    name='MyModel',
                    fields=[
                        ('id', models.AutoField(primary_key=True)),
                    ],
                ),
                migrations.AddField(
                    model_name='mymodel',
                    name='new_col',
                    field=models.IntegerField(),
                ),
                migrations.RemoveField(
                    model_name='mymodel',
                    name='old_col',
                ),
                migrations.DeleteModel(
                    name='OldModel',
                ),
                migrations.RunSQL("UPDATE mymodel SET x = 1"),
            ]
    """)
    (migrations_dir / "0002_update.py").write_text(migration_content)

    provider = DjangoProvider()
    migrations = provider.get_migrations(tmp_path)

    assert len(migrations) == 1
    m = migrations[0]
    assert m.version == "0002"
    assert "CREATE TABLE mymodel" in m.content
    assert "ALTER TABLE mymodel ADD COLUMN new_col" in m.content
    assert "ALTER TABLE mymodel DROP COLUMN old_col" in m.content
    assert "DROP TABLE oldmodel" in m.content
    assert "UPDATE mymodel SET x = 1" in m.content
    assert m.depends_on == ("0001",)
    assert m.metadata["framework"] == "django"
    assert m.metadata["app"] == "myapp"

def test_django_malformed_python(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    migrations_dir = app_dir / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "0001_bad.py").write_text("syntax error!")

    provider = DjangoProvider()
    assert len(provider.get_migrations(tmp_path)) == 0
