from __future__ import annotations

from pathlib import Path

from slowql.migrations.base import MigrationFile, MigrationProvider


class PrismaProvider(MigrationProvider):
    """
    Provider for Prisma migrations, which uses folders like '20240324120000_init/migration.sql'.
    """
    def detect(self, path: Path) -> bool:
        return (path / "schema.prisma").exists() or (path / "migrations").is_dir()

    def get_migrations(self, path: Path) -> list[MigrationFile]:
        migrations_dir = path / "migrations"
        if not migrations_dir.is_dir():
            return []

        migrations = []
        # Prisma folders are named by timestamp_name
        for folder in migrations_dir.iterdir():
            if not folder.is_dir():
                continue

            migration_file = folder / "migration.sql"
            if migration_file.exists():
                version = folder.name
                migrations.append(MigrationFile(
                    version=version,
                    path=migration_file,
                    content=migration_file.read_text()
                ))

        return sorted(migrations, key=lambda m: m.version)
