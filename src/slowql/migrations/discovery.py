from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slowql.migrations.base import MigrationFile, MigrationProvider


class MigrationDiscovery:
    """
    Registry for migration providers and handles auto-detection.
    """

    def __init__(self) -> None:
        self._providers: dict[str, MigrationProvider] = {}

    def register(self, name: str, provider: MigrationProvider) -> None:
        """Register a new migration framework provider."""
        self._providers[name] = provider

    def detect_framework(self, path: Path) -> str | None:
        """
        Detect which migration framework is in use in the given path.
        """
        for name, provider in self._providers.items():
            if provider.detect(path):
                return name
        return None

    def get_migrations(self, path: Path) -> list[MigrationFile]:
        """
        Get all migrations from the detected framework in the given path.
        """
        framework = self.detect_framework(path)
        if not framework:
            return []

        provider = self._providers[framework]
        return provider.get_migrations(path)

    @classmethod
    def default(cls) -> MigrationDiscovery:
        """Create a MigrationDiscovery instance with all built-in providers."""
        from slowql.migrations.providers.alembic import AlembicProvider  # noqa: PLC0415
        from slowql.migrations.providers.django import DjangoProvider  # noqa: PLC0415
        from slowql.migrations.providers.flyway import FlywayProvider  # noqa: PLC0415
        from slowql.migrations.providers.liquibase import LiquibaseProvider  # noqa: PLC0415
        from slowql.migrations.providers.prisma import PrismaProvider  # noqa: PLC0415

        discovery = cls()
        discovery.register("alembic", AlembicProvider())
        discovery.register("django", DjangoProvider())
        discovery.register("flyway", FlywayProvider())
        discovery.register("liquibase", LiquibaseProvider())
        discovery.register("prisma", PrismaProvider())
        return discovery
