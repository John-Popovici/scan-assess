"""scan-assess runner for the vendored Enumeros collector."""

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

    if system == "darwin":
        return "enumeros-macos-arm64" if machine in {"arm64", "aarch64"} else "enumeros-macos-x64"
    if system == "linux":
        return "enumeros-linux-arm64" if machine in {"arm64", "aarch64"} else "enumeros-linux-x64"
    if system == "windows":
        return "enumeros-windows-x64.exe"

    raise RuntimeError(f"Unsupported Enumeros platform: {platform.system()} {platform.machine()}")


class Runner(BaseRunner):
    """Run Enumeros and store its JSON output for scan-assess."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
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
            "note": "Collected live from the machine running scan-assess.",
        }

        output_path = output_dir / "enumeros.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
