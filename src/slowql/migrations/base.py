from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class MigrationFile:
    """
    Represents a single database migration file.

    Attributes:
        version: The version or revision ID of the migration.
        path: The file path to the migration.
        content: The raw content of the migration file.
        depends_on: A list of version IDs this migration depends on.
        metadata: Additional framework-specific metadata.
    """

    version: str
    path: Path
    content: str
    depends_on: Sequence[str] = ()
    metadata: dict[str, Any] = None


class MigrationProvider(ABC):
    """
    Abstract base class for database migration framework providers.
    """

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """
        Check if the given path contains migrations for this framework.
        """
        pass

    @abstractmethod
    def get_migrations(self, path: Path) -> list[MigrationFile]:
        """
        Scan the path and return a list of migration files.
        """
        pass
