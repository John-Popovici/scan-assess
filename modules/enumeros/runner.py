"""scan-assess runner for the vendored Enumeros collector."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path

from src.module_config import load_module_runtime_config
from src.runners.base_runner import BaseRunner


def _binary_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        return "enumeros-macos-arm64" if machine in {"arm64", "aarch64"} else "enumeros-macos-x64"
    if system == "linux":
        return "enumeros-linux-arm64" if machine in {"arm64", "aarch64"} else "enumeros-linux-x64"
    if system == "windows":
        return "enumeros-windows-x64.exe"

    raise RuntimeError(f"Unsupported Enumeros platform: {platform.system()} {platform.machine()}")


def _config_bool(config: dict, key: str, default: bool = False) -> bool:
    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _config_path(module_dir: Path, config: dict, key: str, default: str) -> Path:
    value = str(config.get(key) or default)
    path = Path(value)
    return path if path.is_absolute() else module_dir / path


class Runner(BaseRunner):
    """Run Enumeros and store its JSON output for scan-assess."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        config = load_module_runtime_config(module_dir)
        if _config_bool(config, "demo"):
            fixture_path = _config_path(module_dir, config, "demo_output", "demo_output.json")
            if not fixture_path.exists():
                raise FileNotFoundError(f"Enumeros demo fixture not found: {fixture_path}")
            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise RuntimeError("Enumeros demo fixture must contain a JSON object.")
            data["provenance"] = {
                "data_origin": "demo",
                "collection_method": "module_owned_demo_fixture",
                "live_collection": False,
                "fixture": str(fixture_path),
                "sample_data": True,
                "demo": True,
                "note": "Bundled Enumeros demonstration inventory; do not treat as live local host telemetry.",
            }
            output_path = output_dir / "enumeros.json"
            output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            return True, [output_path]

        binary = Path(os.environ.get("SCAN_ASSESS_ENUMEROS_BIN", module_dir / "bin" / _binary_name()))
        timeout = int(os.environ.get("SCAN_ASSESS_ENUMEROS_TIMEOUT", "120"))

        if not binary.exists():
            raise FileNotFoundError(f"Enumeros binary not found: {binary}")

        completed = subprocess.run(
            [str(binary)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"Enumeros exited with {completed.returncode}")

        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Enumeros did not return valid JSON: {exc}") from exc

        data["provenance"] = {
            "data_origin": "live",
            "collection_method": "local_host_inventory",
            "live_collection": True,
            "binary": str(binary),
            "sample_data": False,
            "demo": False,
            "note": "Collected live from the machine running scan-assess.",
        }

        output_path = output_dir / "enumeros.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
