from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import OrgProfile


def load_yaml(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data


def load_scoring_rules(path: str | Path) -> dict[str, Any]:
    return load_yaml(path)


def load_source_config(path: str | Path) -> dict[str, Any]:
    return load_yaml(path)


def load_org_profile(path: str | Path) -> OrgProfile:
    return OrgProfile.model_validate(load_yaml(path))


def load_allowlist_domains(path: str | Path) -> list[str]:
    path = Path(path)
    if not path.exists():
        return []
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
