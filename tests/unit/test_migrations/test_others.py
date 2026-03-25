from slowql.migrations.providers.flyway import FlywayProvider
from slowql.migrations.providers.prisma import PrismaProvider


def test_flyway_provider(tmp_path):
    provider = FlywayProvider()
    assert provider.detect(tmp_path) is False

    (tmp_path / "V1__init.sql").write_text("CREATE TABLE x (id INT);")
    (tmp_path / "V2__add.sql").write_text("ALTER TABLE x ADD COLUMN y INT;")
    (tmp_path / "not_a_migration.sql").write_text("SELECT 1;")
    (tmp_path / "U1__undo.sql").write_text("DROP TABLE x;")

    assert provider.detect(tmp_path) is True
    migrations = provider.get_migrations(tmp_path)

    assert len(migrations) == 2
    assert migrations[0].version == "1"
    assert migrations[1].version == "2"
    assert "CREATE TABLE x" in migrations[0].content

def test_prisma_provider(tmp_path):
    provider = PrismaProvider()
    # detect expects migrations folder in the path passed
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir(parents=True)

    m1_dir = migrations_dir / "20230101000000_init"
    m1_dir.mkdir()
    (m1_dir / "migration.sql").write_text("CREATE TABLE User (id INT);")

    m2_dir = migrations_dir / "20230102000000_add_profile"
    m2_dir.mkdir()
    (m2_dir / "migration.sql").write_text("CREATE TABLE Profile (id INT);")

    assert provider.detect(tmp_path) is True
    migrations = provider.get_migrations(tmp_path)

    assert len(migrations) == 2
    assert migrations[0].version == "20230101000000_init"
    assert "User" in migrations[0].content
