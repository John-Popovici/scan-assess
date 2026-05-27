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
