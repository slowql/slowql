from __future__ import annotations

import re
from pathlib import Path

from slowql.migrations.base import MigrationFile, MigrationProvider


class LiquibaseProvider(MigrationProvider):
    """
    Provider for Liquibase migrations, focusing on 'formatted SQL' files.
    """
    def detect(self, path: Path) -> bool:
        # Check for files starting with --liquibase formatted sql
        for file in path.glob("*.sql"):
            try:
                content = file.read_text()
                if "--liquibase formatted sql" in content.lower():
                    return True
            except Exception:
                continue
        return False

    def get_migrations(self, path: Path) -> list[MigrationFile]:
        migrations = []
        for file in path.glob("*.sql"):
            try:
                content = file.read_text()
                if "--liquibase formatted sql" not in content.lower():
                    continue

                # Extract changesets
                # Pattern: --changeset author:id attributes...
                changesets = re.findall(r"--changeset\s+([\w\.-]+):([\w\.-]+).*\n(.*?)(?=\n--changeset|\Z)", content, re.DOTALL)

                for i, (author, change_id, sql) in enumerate(changesets):
                    version = f"{file.stem}_{i}_{change_id}"
                    migrations.append(MigrationFile(
                        version=version,
                        path=file,
                        content=sql.strip(),
                        metadata={"author": author, "framework": "liquibase"}
                    ))
            except Exception:
                continue

        # Sorting Liquibase is tricky if multiple files, usually order is defined in a changelog.xml
        # For now, we sort by filename and index.
        return sorted(migrations, key=lambda m: m.version)
