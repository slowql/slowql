from __future__ import annotations

import re
from pathlib import Path

from slowql.migrations.base import MigrationFile, MigrationProvider


class FlywayProvider(MigrationProvider):
    def detect(self, path: Path) -> bool:
        return any(path.glob("V*__*.sql")) or any(path.glob("U*__*.sql"))

    def get_migrations(self, path: Path) -> list[MigrationFile]:
        migrations = []
        for file in path.glob("V*__*.sql"):
            match = re.match(r"V(\d+)__.*\.sql", file.name)
            if match:
                version = match.group(1)
                migrations.append(MigrationFile(
                    version=version,
                    path=file,
                    content=file.read_text()
                ))
        return sorted(migrations, key=lambda m: int(m.version))
