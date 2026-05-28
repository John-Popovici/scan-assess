from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from .io_utils import today_parts


@dataclass(frozen=True)
class ProjectPaths:
    project_root: Path

    @classmethod
    def discover(cls, start: str | Path | None = None) -> "ProjectPaths":
        current = Path(start or Path.cwd()).resolve()
        for candidate in [current, *current.parents]:
            if (candidate / "pyproject.toml").exists() and (candidate / "src" / "ngo_intel").exists():
                return cls(candidate)
        return cls(current)

    @property
    def config_dir(self) -> Path:
        return self.project_root / "config"

    @property
    def data_dir(self) -> Path:
        return self.project_root / "data"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def normalized_dir(self) -> Path:
        return self.data_dir / "normalized"

    @property
    def scored_dir(self) -> Path:
        return self.data_dir / "scored"

    @property
    def agent_context_dir(self) -> Path:
        return self.data_dir / "agent_context"

    @property
    def local_context_dir(self) -> Path:
        return self.project_root / "local_context"

    def normalized_date_dir(self, value: date | datetime | None = None) -> Path:
        year, month, day = today_parts(value)
        return self.normalized_dir / year / month / day

    def scored_date_dir(self, value: date | datetime | None = None) -> Path:
        year, month, day = today_parts(value)
        return self.scored_dir / year / month / day

    def raw_source_date_dir(self, source: str, value: date | datetime | None = None) -> Path:
        year, month, day = today_parts(value)
        return self.raw_dir / source / year / month / day
