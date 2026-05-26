"""scan-assess runner for the vendored SafeSniff collector."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path

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


class Runner(BaseRunner):
    """Run SafeSniff with conservative defaults and store JSON output."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
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
            "note": (
                "Live target detection only; no TCP service scan was performed."
                if mode == "detect"
                else "Live low-impact TCP service scan. Treat open ports as exposure evidence, not proof of compromise."
            ),
        }

        output_path = output_dir / "safesniff.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
