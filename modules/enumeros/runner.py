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

    def validation_options(self) -> dict:
        return {
            "conditions": {
                "off": "Off",
                "nominal": "Nominal: current OS and browser inventory",
                "weak_issue": "Weak issue: browser patch gap",
                "actionable_issue": "Actionable issue: unsupported OS with exposed services",
            },
            "scopes": {
                "local_device": "Local device inventory",
                "observed_device": "Observed non-local device inventory",
            },
            "default_condition": "weak_issue",
            "default_scope": "local_device",
            "supports_true_positive": True,
        }

    def generate_validation_evidence(self, condition: str = "nominal", scope: str = "local_device", **_: object) -> list[dict]:
        if condition == "off":
            return []
        if condition == "actionable_issue":
            inventory_host = "accounts-workstation-07" if scope == "observed_device" else "office-laptop-01"
            payload = {
                "module": "enumeros",
                "provenance": {"data_origin": "local_inventory", "sample_data": False},
                "hostname": inventory_host,
                "asset_context": {
                    "device_scope": "observed_non_local_device" if scope == "observed_device" else "local_device",
                    "is_local_host": scope != "observed_device",
                    "inventory_method": "imported_or_agent_supplied_inventory" if scope == "observed_device" else "local_inventory",
                    "reporting_hint": "Distinguish this asset from the scan-assess host when writing findings.",
                },
                "os": {
                    "platform": "windows",
                    "product_name": "Windows 11",
                    "display_version": "21H2",
                    "build_number": 22000,
                    "support_status": "unsupported_or_out_of_servicing",
                },
                "browsers": {"edge": "145.0.3720.10", "chrome": "123.0.6312.86"},
                "version_status": {
                    "items": [
                        {"name": "os", "installed": "21H2", "latest": "25H2", "status": "outdated", "source": "Windows release policy"},
                        {"name": "chrome", "installed": "123.0.6312.86", "latest": "149.0.7827.29", "status": "outdated", "source": "Chrome Version History API"},
                    ]
                },
                "network_discovery": {
                    "method": "tcp_connect",
                    "local_ip": "10.40.12.44",
                    "assumed_subnet": "10.40.12.0/24",
                    "hosts": [{"ip": "10.40.12.44", "open_ports": [{"port": 445, "status": "open"}, {"port": 3389, "status": "open"}]}],
                },
                "summary": {"overall": "critical", "outdated_count": 2, "open_service_count": 2},
            }
        else:
            browser_version = "123.0.6312.86" if condition == "weak_issue" else "149.0.7827.29"
            inventory_host = "volunteer-laptop-03" if scope == "observed_device" else "office-laptop-01"
            payload = {
                "module": "enumeros",
                "provenance": {"data_origin": "local_inventory", "sample_data": False},
                "hostname": inventory_host,
                "asset_context": {
                    "device_scope": "observed_non_local_device" if scope == "observed_device" else "local_device",
                    "is_local_host": scope != "observed_device",
                    "inventory_method": "imported_or_agent_supplied_inventory" if scope == "observed_device" else "local_inventory",
                    "reporting_hint": "Distinguish this asset from the scan-assess host when writing findings.",
                },
                "os": {"platform": "macos", "product_name": "macOS", "product_version": "26.5", "support_status": "current"},
                "browsers": {"chrome": browser_version, "safari": "26.5"},
                "version_status": {
                    "items": [
                        {"name": "os", "installed": "26.5", "latest": "26.5", "status": "current", "source": "OS vendor release policy"},
                        {
                            "name": "chrome",
                            "installed": browser_version,
                            "latest": "149.0.7827.29",
                            "status": "outdated" if condition == "weak_issue" else "current",
                            "source": "Chrome Version History API",
                        },
                    ]
                },
                "summary": {"overall": "warnings" if condition == "weak_issue" else "ok", "outdated_count": 1 if condition == "weak_issue" else 0, "open_service_count": 0},
            }
        return [{"filename": "enumeros/enumeros.json", "file_data": payload}]

    def generate_validation_noise(self, noise_level: int = 0, **_: object) -> list[dict]:
        noise_count = max(0, min(int(noise_level), 100))
        if noise_count < 10:
            return []
        return [
            {
                "filename": "enumeros/current_asset_inventory.json",
                "file_data": {
                    "module": "enumeros",
                    "provenance": {"data_origin": "operator_supplied_inventory", "sample_data": False},
                    "assets": [
                        {
                            "hostname": f"staff-laptop-{idx:02d}",
                            "asset_context": {"device_scope": "imported_inventory", "is_local_host": False},
                            "os": {"platform": "macos", "support_status": "current"},
                            "browsers": {"chrome": "149.0.7827.29", "safari": "26.5"},
                            "summary": {"overall": "ok"},
                        }
                        for idx in range(1, min(noise_count // 10, 6) + 1)
                    ],
                },
            }
        ]

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
