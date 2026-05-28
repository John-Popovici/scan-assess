from __future__ import annotations

from datetime import date
from typing import Protocol

from ngo_intel.paths import ProjectPaths


class BaseSource(Protocol):
    name: str

    def fetch_raw(self, paths: ProjectPaths, date: date | None = None) -> None:
        """Fetch raw evidence. Fixture-first adapters may intentionally do nothing."""

    def normalize(self, paths: ProjectPaths, date: date | None = None) -> list[object]:
        """Normalize raw evidence into analyst-friendly models."""
        ...
