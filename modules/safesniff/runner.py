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

    def validation_options(self) -> dict:
        return {
            "conditions": {
                "off": "Off",
                "nominal": "Nominal: target detection only",
                "weak_issue": "Weak issue: medium-risk admin surface",
                "actionable_issue": "Actionable issue: high-risk exposed services",
            },
            "scopes": {"observed_network": "Observed network device"},
            "default_condition": "nominal",
            "default_scope": "observed_network",
            "supports_true_positive": True,
        }

    def generate_validation_evidence(self, condition: str = "nominal", scope: str = "observed_network", **_: object) -> list[dict]:
        if condition == "off":
            return []
        if condition == "actionable_issue":
            payload = {
                "module": "safesniff",
                "tool": "safesniff",
                "mode": "permissioned_safe_tcp_enumeration",
                "profile": "thorough",
                "provenance": {"active_network_scan": True, "total_tcp_connect_attempts_planned": 28448, "sample_data": False},
                "target": "10.40.12.0/24",
                "asset_context": {
                    "device_scope": scope,
                    "is_local_host": False,
                    "reporting_hint": "SafeSniff findings are observed network devices and services, not local host inventory.",
                },
                "device_inventory": {
                    "observed_device_count": 4,
                    "active_with_open_services": 3,
                    "devices": [
                        {
                            "ip": "10.40.12.44",
                            "label": "accounts-workstation-07",
                            "likely_role": "windows_workstation_or_file_sharing_host",
                            "exposure_level": "high",
                            "open_ports": [135, 139, 445, 3389],
                            "security_review_priority": "high",
                            "risk_tags": ["file_sharing_or_rpc_surface", "remote_admin_surface"],
                        },
                        {
                            "ip": "10.40.12.20",
                            "label": "nas-finance",
                            "likely_role": "file_server_or_nas",
                            "exposure_level": "high",
                            "open_ports": [445, 5000, 5001],
                            "security_review_priority": "high",
                            "risk_tags": ["file_sharing_or_rpc_surface", "web_admin_or_app_surface"],
                        },
                    ],
                },
                "hosts": [
                    {
                        "ip": "10.40.12.44",
                        "services": [
                            {"port": 445, "service": "smb", "severity": "high", "category": "file_sharing_or_rpc", "remediation": "Restrict SMB to trusted hosts and verify patch level."},
                            {"port": 3389, "service": "rdp", "severity": "high", "category": "remote_admin", "remediation": "Disable or restrict RDP; require VPN/MFA."},
                        ],
                    }
                ],
                "summary": {"overall": "critical", "high_count": 2, "medium_count": 1, "open_service_count": 7},
            }
        elif condition == "weak_issue":
            payload = {
                "module": "safesniff",
                "tool": "safesniff",
                "mode": "permissioned_safe_tcp_enumeration",
                "provenance": {"active_network_scan": True, "total_tcp_connect_attempts_planned": 256, "sample_data": False},
                "target": "198.51.100.0/24",
                "asset_context": {
                    "device_scope": scope,
                    "is_local_host": False,
                    "reporting_hint": "SafeSniff findings are observed network devices and services, not local host inventory.",
                },
                "device_inventory": {
                    "observed_device_count": 3,
                    "active_with_open_services": 1,
                    "devices": [
                        {
                            "ip": "198.51.100.1",
                            "label": "gateway",
                            "likely_role": "router_or_gateway",
                            "exposure_level": "medium",
                            "open_ports": [80, 443],
                            "security_review_priority": "medium",
                            "risk_tags": ["web_admin_or_app_surface"],
                        }
                    ],
                },
                "summary": {"overall": "warnings", "high_count": 0, "medium_count": 1, "open_service_count": 2},
            }
        else:
            payload = {
                "module": "safesniff",
                "mode": "target_detection_only",
                "provenance": {"active_network_scan": False, "total_tcp_connect_attempts_planned": 0},
                "asset_context": {
                    "device_scope": scope,
                    "is_local_host": False,
                    "reporting_hint": "Target detection does not prove services are open.",
                },
                "note": "Target was selected, but no TCP service scan was run.",
            }
        return [{"filename": "safesniff/safesniff.json", "file_data": payload}]

    def generate_validation_noise(self, noise_level: int = 0, **_: object) -> list[dict]:
        noise_count = max(0, min(int(noise_level), 100))
        if noise_count < 25:
            return []
        return [
            {
                "filename": "safesniff/permitted_service_inventory.json",
                "file_data": {
                    "module": "safesniff",
                    "mode": "permissioned_safe_tcp_enumeration",
                    "provenance": {"active_network_scan": True, "sample_data": False},
                    "asset_context": {
                        "device_scope": "observed_network",
                        "is_local_host": False,
                        "observed_by": "office-network-sensor-01",
                    },
                    "hosts": [
                        {"ip": "10.40.12.10", "services": [{"port": 443, "service": "https", "severity": "info", "encryption": "tls"}]},
                        {"ip": "10.40.12.11", "services": [{"port": 53, "service": "dns", "severity": "info"}]},
                    ],
                    "summary": {"overall": "ok", "high_count": 0, "medium_count": 0},
                },
            }
        ]

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
                else "Live low-impact TCP service scan. Treat open ports as exposure telemetry, not proof of compromise."
            ),
        }

        output_path = output_dir / "safesniff.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
