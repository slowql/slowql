import textwrap

from slowql.core.config import AnalysisConfig, Config
from slowql.core.engine import SlowQL


def test_alembic_scenario(tmp_path):
    # Setup a project with Alembic migrations and a "bad" query
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    versions_dir = project_dir / "migrations" / "versions"
    versions_dir.mkdir(parents=True)

    # M1: Create users table
    m1_content = textwrap.dedent("""
        revision = '1'
        down_revision = None
        def upgrade():
            op.create_table('users', op.Column('id', op.Integer))
    """)
    (versions_dir / "001_init.py").write_text(m1_content)

    # M2: Drop users table (Breaking Change!)
    m2_content = textwrap.dedent("""
        revision = '2'
        down_revision = '1'
        def upgrade():
            op.drop_table('users')
    """)
    (versions_dir / "002_drop.py").write_text(m2_content)

    # Run SlowQL with explicit dialect
    config = Config(analysis=AnalysisConfig(dialect="postgres"))
    engine = SlowQL(config)
    result = engine.analyze_files(paths=[str(project_dir)])

    # We expect MIG-BRK-001 for M2
    migration_issues = [i for i in result.issues if i.rule_id == "MIG-BRK-001"]
    assert len(migration_issues) >= 1
    assert any("Dropping table 'users'" in i.message for i in migration_issues)

def test_alembic_column_drop(tmp_path):
    project_dir = tmp_path / "alembic_col"
    project_dir.mkdir()
    versions_dir = project_dir / "migrations" / "versions"
    versions_dir.mkdir(parents=True)

    m1 = textwrap.dedent("""
        revision = '1'
        down_revision = None
        def upgrade():
            op.create_table('users', op.Column('id', op.Integer), op.Column('email', op.String))
    """)
    (versions_dir / "001_init.py").write_text(m1)

    m2 = textwrap.dedent("""
        revision = '2'
        down_revision = '1'
        def upgrade():
            op.drop_column('users', 'email')
    """)
    (versions_dir / "002_drop_col.py").write_text(m2)

    engine = SlowQL(Config(analysis=AnalysisConfig(dialect="postgres")))
    result = engine.analyze_files(paths=[str(project_dir)])
    migration_issues = [i for i in result.issues if i.rule_id == "MIG-BRK-001"]
    assert len(migration_issues) >= 1
    assert any("Dropping column 'email' from table 'users'" in i.message for i in migration_issues)

def test_django_scenario(tmp_path):
    # Setup a Django-like project
    project_dir = tmp_path / "django_project"
    project_dir.mkdir()

    app_dir = project_dir / "myapp"
    app_dir.mkdir()
    migrations_dir = app_dir / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "__init__.py").write_text("")

    # 0001_initial: Create Profile
    m1_content = textwrap.dedent("""
        from django.db import migrations, models
        class Migration(migrations.Migration):
            dependencies = []
            operations = [
                migrations.CreateModel(name='Profile', fields=[('id', models.AutoField(primary_key=True))])
            ]
    """)
    (migrations_dir / "0001_initial.py").write_text(m1_content)

    # 0002_drop: Drop Profile
    m2_content = textwrap.dedent("""
        from django.db import migrations, models
        class Migration(migrations.Migration):
            dependencies = [('myapp', '0001_initial')]
            operations = [
                migrations.DeleteModel(name='Profile')
            ]
    """)
    (migrations_dir / "0002_drop.py").write_text(m2_content)

    config = Config(analysis=AnalysisConfig(dialect="postgres"))
    engine = SlowQL(config)
    result = engine.analyze_files(paths=[str(project_dir)])

    migration_issues = [i for i in result.issues if i.rule_id == "MIG-BRK-001"]
    assert len(migration_issues) >= 1
    assert any("Dropping table 'profile'" in i.message for i in migration_issues)

def test_django_column_drop(tmp_path):
    project_dir = tmp_path / "django_col"
    project_dir.mkdir()
    app_dir = project_dir / "myapp"
    app_dir.mkdir()
    migrations_dir = app_dir / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "__init__.py").write_text("")

    m1 = textwrap.dedent("""
        from django.db import migrations, models
        class Migration(migrations.Migration):
            dependencies = []
            operations = [
                migrations.CreateModel(name='Profile', fields=[('id', models.AutoField(primary_key=True)), ('bio', models.TextField())])
            ]
    """)
    (migrations_dir / "0001_initial.py").write_text(m1)

    m2 = textwrap.dedent("""
        from django.db import migrations, models
        class Migration(migrations.Migration):
            dependencies = [('myapp', '0001_initial')]
            operations = [
                migrations.RemoveField(model_name='profile', name='bio')
            ]
    """)
    (migrations_dir / "0002_drop_col.py").write_text(m2)

    engine = SlowQL(Config(analysis=AnalysisConfig(dialect="postgres")))
    result = engine.analyze_files(paths=[str(project_dir)])
    migration_issues = [i for i in result.issues if i.rule_id == "MIG-BRK-001"]
    assert len(migration_issues) >= 1
    assert any("Dropping column 'bio' from table 'profile'" in i.message for i in migration_issues)

def test_flyway_scenario(tmp_path):
    # Setup Flyway project
    project_dir = tmp_path / "flyway_project"
    project_dir.mkdir()

    (project_dir / "V1__init.sql").write_text("CREATE TABLE logs (id INT);")
    (project_dir / "V2__drop.sql").write_text("DROP TABLE logs;")

    config = Config(analysis=AnalysisConfig(dialect="postgres"))
    engine = SlowQL(config)
    result = engine.analyze_files(paths=[str(project_dir)])

    migration_issues = [i for i in result.issues if i.rule_id == "MIG-BRK-001"]
    assert len(migration_issues) >= 1
    assert any("Dropping table 'logs'" in i.message for i in migration_issues)
