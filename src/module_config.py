from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RUNTIME_CONFIG_NAME = "scan_assess_runtime.json"


def module_runtime_config_path(module_dir: Path) -> Path:
    return module_dir / "config" / RUNTIME_CONFIG_NAME


def load_module_runtime_config(module_dir: Path) -> dict[str, Any]:
    path = module_runtime_config_path(module_dir)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def write_module_runtime_config(module_dir: Path, values: dict[str, Any]) -> Path:
    path = module_runtime_config_path(module_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_module_runtime_config(module_dir)
    for key, value in values.items():
        if value is None:
            existing.pop(key, None)
        else:
            existing[key] = value
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def parse_override_value(raw: str) -> Any:
    text = raw.strip()
    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"none", "null"}:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def parse_set_arguments(set_args: list[str]) -> dict[str, dict[str, Any]]:
    overrides: dict[str, dict[str, Any]] = {}
    for raw in set_args:
        if "=" not in raw:
            raise ValueError(f"Invalid --set value (missing '='): {raw}")
        key_part, value_part = raw.split("=", 1)
        if "." not in key_part:
            raise ValueError(f"Invalid --set value (missing module prefix): {raw}")
        module_name, key = key_part.split(".", 1)
        module_name = module_name.strip()
        key = key.strip()
        if not module_name or not key:
            raise ValueError(f"Invalid --set value (empty module or key): {raw}")
        overrides.setdefault(module_name, {})[key] = parse_override_value(value_part)
    return overrides


def apply_runtime_overrides(
    module_dir: Path,
    *,
    module_name: str,
    module_overrides: dict[str, dict[str, Any]] | None = None,
    generic_overrides: dict[str, Any] | None = None,
) -> list[str]:
    applied: dict[str, Any] = {}
    if generic_overrides:
        applied.update(generic_overrides)
    if module_overrides and module_name in module_overrides:
        applied.update(module_overrides[module_name])
    if not applied:
        return []

    write_module_runtime_config(module_dir, applied)
    keys = ", ".join(sorted(applied.keys()))
    return [f"{module_name}: applied config overrides ({keys})"]
