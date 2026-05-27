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
        data = scanner.scan_site(config)
        output_path = output_dir / "sitechecker.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
