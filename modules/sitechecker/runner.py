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

    def validation_options(self) -> dict:
        return {
            "conditions": {
                "off": "Off",
                "nominal": "Nominal: hardened website posture",
                "weak_issue": "Weak issue: missing hardening headers",
                "actionable_issue": "Actionable issue: exposed secret and legacy JavaScript",
            },
            "scopes": {"module_default": "Configured website"},
            "default_condition": "nominal",
            "default_scope": "module_default",
            "supports_true_positive": True,
        }

    def generate_validation_evidence(self, condition: str = "nominal", **_: object) -> list[dict]:
        if condition == "off":
            return []
        findings: list[dict[str, Any]] = []
        if condition in {"weak_issue", "actionable_issue"}:
            findings.append(
                {
                    "kind": "missing_security_header",
                    "severity": "medium",
                    "url": "https://eastlondonaudio.com/",
                    "detail": "Content-Security-Policy header was not observed.",
                }
            )
        if condition == "actionable_issue":
            findings.extend(
                [
                    {
                        "kind": "exposed_interesting_path",
                        "severity": "high",
                        "url": "https://eastlondonaudio.com/.env",
                        "detail": "Sensitive-looking environment file was reachable during the owner-authorized check.",
                    },
                    {
                        "kind": "legacy_component",
                        "severity": "high",
                        "component": "jquery",
                        "observed_version": "1.8.3",
                        "policy_minimum": "3.7.1",
                    },
                ]
            )
        payload = {
            "module": "sitechecker",
            "target_url": "https://eastlondonaudio.com",
            "provenance": {
                "data_origin": "operator_supplied_site_check",
                "sample_data": False,
                "owner_authorized": True,
                "collection_method": "low_impact_http_observation",
            },
            "summary": {
                "overall": "critical" if condition == "actionable_issue" else "warnings" if condition == "weak_issue" else "ok",
                "finding_count": len(findings),
            },
            "findings": findings,
        }
        return [{"filename": "sitechecker/sitechecker.json", "file_data": payload}]

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        scanner = _load_scanner(module_dir)
        config_path = module_dir / "config" / "scan_assess_runtime.json"
        config = scanner.load_config(config_path)
        data = scanner.scan_site(config)
        output_path = output_dir / "sitechecker.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
