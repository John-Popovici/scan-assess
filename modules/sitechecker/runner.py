"""scan-assess runner for owner-authorized website exposure checks."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from src.runners.base_runner import BaseRunner


def _load_scanner(module_dir: Path) -> Any:
    scanner_path = module_dir / "source" / "scanner.py"
    spec = importlib.util.spec_from_file_location("sitechecker_scanner", scanner_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load SiteChecker scanner: {scanner_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Runner(BaseRunner):
    """Run SiteChecker against the configured owner-authorized website."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        scanner = _load_scanner(module_dir)
        config_path = module_dir / "config" / "scan_assess_runtime.json"
        config = scanner.load_config(config_path)
        if _config_bool(config, "demo"):
            fixture_path = _config_path(module_dir, config, "demo_output", "demo_output.json")
            if not fixture_path.exists():
                raise FileNotFoundError(f"SiteChecker demo fixture not found: {fixture_path}")
            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise RuntimeError("SiteChecker demo fixture must contain a JSON object.")
            data["provenance"] = {
                "data_origin": "demo",
                "collection_method": "module_owned_demo_fixture",
                "live_collection": False,
                "active_network_scan": False,
                "fixture": str(fixture_path),
                "sample_data": True,
                "demo": True,
                "scope_note": "Bundled SiteChecker demonstration website telemetry; no HTTP requests were made.",
            }
            output_path = output_dir / "sitechecker.json"
            output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            return True, [output_path]

        data = scanner.scan_site(config)
        output_path = output_dir / "sitechecker.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]


def _config_bool(config: dict[str, Any], key: str, default: bool = False) -> bool:
    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _config_path(module_dir: Path, config: dict[str, Any], key: str, default: str) -> Path:
    value = str(config.get(key) or default)
    path = Path(value)
    return path if path.is_absolute() else module_dir / path
