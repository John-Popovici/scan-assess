from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .paths import ProjectPaths


CONFIG_FILES = [
    Path("config/org_profile.yaml"),
    Path("config/scoring_rules.yaml"),
    Path("config/source_config.yaml"),
    Path("config/allowlist_domains.txt"),
    Path("local_context/org/brands_used.txt"),
    Path("local_context/org/domains.txt"),
    Path("local_context/org/org_profile.yaml"),
    Path("local_context/users/competency_profile.yaml"),
]

CONFIG_DIRS = [
    Path("config/profiles"),
]


@dataclass(frozen=True)
class ConfigSet:
    name: str
    path: Path
    active: bool
    files_present: int
    files_total: int


def config_sets_dir(paths: ProjectPaths) -> Path:
    return paths.project_root / "config_sets"


def config_set_path(paths: ProjectPaths, name: str) -> Path:
    safe_name = _safe_name(name)
    return config_sets_dir(paths) / safe_name


def list_config_sets(paths: ProjectPaths) -> list[ConfigSet]:
    root = config_sets_dir(paths)
    names = sorted(path.name for path in root.iterdir() if path.is_dir()) if root.exists() else []
    return [_describe_config_set(paths, name) for name in names]


def ensure_default_config_set(paths: ProjectPaths) -> ConfigSet:
    target = config_set_path(paths, "default")
    if not target.exists():
        save_active_as_config_set(paths, "default", overwrite=True)
    return _describe_config_set(paths, "default")


def save_active_as_config_set(paths: ProjectPaths, name: str, overwrite: bool = False) -> ConfigSet:
    target = config_set_path(paths, name)
    if target.exists() and not overwrite:
        raise FileExistsError(f"Config set already exists: {target}")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    for rel in CONFIG_FILES:
        src = paths.project_root / rel
        if src.exists():
            dst = target / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    for rel in CONFIG_DIRS:
        src = paths.project_root / rel
        if src.exists():
            shutil.copytree(src, target / rel, dirs_exist_ok=True)
    return _describe_config_set(paths, name)


def apply_config_set(paths: ProjectPaths, name: str) -> ConfigSet:
    source = config_set_path(paths, name)
    if not source.exists():
        raise FileNotFoundError(f"Config set does not exist: {source}")
    for rel in CONFIG_FILES:
        src = source / rel
        if src.exists():
            dst = paths.project_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    for rel in CONFIG_DIRS:
        src = source / rel
        if src.exists():
            dst = paths.project_root / rel
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
    (config_sets_dir(paths) / ".active").write_text(_safe_name(name) + "\n", encoding="utf-8")
    return _describe_config_set(paths, name)


def apply_config_overrides(
    paths: ProjectPaths,
    *,
    org_profile: str | Path | None = None,
    scoring_rules: str | Path | None = None,
    source_config: str | Path | None = None,
    allowlist: str | Path | None = None,
    brands: str | Path | None = None,
    domains: str | Path | None = None,
) -> list[str]:
    copies = {
        org_profile: Path("config/org_profile.yaml"),
        scoring_rules: Path("config/scoring_rules.yaml"),
        source_config: Path("config/source_config.yaml"),
        allowlist: Path("config/allowlist_domains.txt"),
        brands: Path("local_context/org/brands_used.txt"),
        domains: Path("local_context/org/domains.txt"),
    }
    applied: list[str] = []
    for src_value, rel_dst in copies.items():
        if src_value is None:
            continue
        src = Path(src_value).expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(f"Config override not found: {src}")
        dst = paths.project_root / rel_dst
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        applied.append(str(rel_dst))
    return applied


def read_config_file(paths: ProjectPaths, config_set: str, rel_path: str | Path) -> str:
    path = config_set_path(paths, config_set) / Path(rel_path)
    return path.read_text(encoding="utf-8") if path.exists() else ""


def write_config_file(paths: ProjectPaths, config_set: str, rel_path: str | Path, text: str) -> None:
    rel = Path(rel_path)
    if rel not in CONFIG_FILES:
        raise ValueError(f"Unsupported config file: {rel}")
    path = config_set_path(paths, config_set) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def active_config_set_name(paths: ProjectPaths) -> str:
    marker = config_sets_dir(paths) / ".active"
    if marker.exists():
        value = marker.read_text(encoding="utf-8").strip()
        if value:
            return value
    return "default"


def _describe_config_set(paths: ProjectPaths, name: str) -> ConfigSet:
    set_path = config_set_path(paths, name)
    files_present = sum(1 for rel in CONFIG_FILES if (set_path / rel).exists())
    active = active_config_set_name(paths) == _safe_name(name)
    return ConfigSet(
        name=_safe_name(name),
        path=set_path,
        active=active,
        files_present=files_present,
        files_total=len(CONFIG_FILES),
    )


def _safe_name(name: str) -> str:
    cleaned = "".join(ch for ch in name.strip().lower() if ch.isalnum() or ch in {"-", "_"})
    if not cleaned:
        raise ValueError("Config set name cannot be empty")
    return cleaned
