"""scan-assess runner for the vendored SafeSniff collector."""

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

    if system == "darwin" and machine in {"arm64", "aarch64"}:
        return "safesniff-macos-arm64"
    if system == "darwin":
        return "safesniff-macos-x64"
    if system == "linux":
        return "safesniff-linux-arm64" if machine in {"arm64", "aarch64"} else "safesniff-linux-x64"
    if system == "windows":
        return "safesniff-windows-x64.exe"

    raise RuntimeError(f"Unsupported SafeSniff platform: {platform.system()} {platform.machine()}")


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
    """Run SafeSniff with conservative defaults and store JSON output."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        config = load_module_runtime_config(module_dir)
        if _config_bool(config, "demo"):
            fixture_path = _config_path(module_dir, config, "demo_output", "demo_output.json")
            if not fixture_path.exists():
                raise FileNotFoundError(f"SafeSniff demo fixture not found: {fixture_path}")
            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise RuntimeError("SafeSniff demo fixture must contain a JSON object.")
            data["provenance"] = {
                "data_origin": "demo",
                "collection_method": "module_owned_demo_fixture",
                "live_collection": False,
                "active_network_scan": False,
                "fixture": str(fixture_path),
                "sample_data": True,
                "demo": True,
                "note": "Bundled SafeSniff demonstration network telemetry; no live target detection or TCP scan was performed.",
            }
            output_path = output_dir / "safesniff.json"
            output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            return True, [output_path]

        binary = Path(os.environ.get("SCAN_ASSESS_SAFESNIFF_BIN", module_dir / "bin" / _binary_name()))
        timeout = int(os.environ.get("SCAN_ASSESS_SAFESNIFF_TIMEOUT", "180"))
        mode = os.environ.get("SCAN_ASSESS_SAFESNIFF_MODE", "detect").strip().lower()

        if binary.exists():
            command = [str(binary)]
        else:
            manifest_path = module_dir / "source" / "Cargo.toml"
            if not manifest_path.exists():
                raise FileNotFoundError(f"SafeSniff binary not found and source manifest missing: {binary}")
            command = ["cargo", "run", "--quiet", "--manifest-path", str(manifest_path), "--"]

        if mode == "detect":
            command.append("--detect-target")
        elif mode == "scan":
            command.extend(["--profile", os.environ.get("SCAN_ASSESS_SAFESNIFF_PROFILE", "light")])
            target = os.environ.get("SCAN_ASSESS_SAFESNIFF_TARGET")
            if target:
                command.extend(["--target", target])
        else:
            raise RuntimeError("SCAN_ASSESS_SAFESNIFF_MODE must be 'detect' or 'scan'")

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"SafeSniff exited with {completed.returncode}")

        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"SafeSniff did not return valid JSON: {exc}") from exc

        data["provenance"] = {
            "data_origin": "live",
            "collection_method": "target_detection" if mode == "detect" else "tcp_service_scan",
            "live_collection": True,
            "active_network_scan": mode == "scan",
            "binary": str(binary) if binary.exists() else "cargo run from vendored source",
            "sample_data": False,
            "demo": False,
            "note": (
                "Live target detection only; no TCP service scan was performed."
                if mode == "detect"
                else "Live low-impact TCP service scan. Treat open ports as exposure evidence, not proof of compromise."
            ),
        }

        output_path = output_dir / "safesniff.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
