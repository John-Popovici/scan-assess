from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = PROJECT_ROOT / "config" / "scenarios"


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    mode: str
    prompt_profile: str
    dnscap_log_root: str | None
    threatsucker_config_set: str | None
    include_demo_threat_intel: bool
    expected_findings: list[str]
    module_tests: dict[str, str]
    actionable_evidence: list[str]
    background_evidence: list[str]


def _scenario_path(name: str) -> Path:
    safe_name = name.strip().replace("/", "-")
    return SCENARIO_DIR / f"{safe_name}.yaml"


def list_scenarios() -> list[str]:
    if not SCENARIO_DIR.exists():
        return []
    return sorted(path.stem for path in SCENARIO_DIR.glob("*.yaml"))


def load_scenario(name: str) -> Scenario:
    path = _scenario_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Scenario not found: {name}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Scenario(
        name=str(raw.get("name") or name),
        description=str(raw.get("description") or ""),
        mode=str(raw.get("mode") or "live"),
        prompt_profile=str(raw.get("prompt_profile") or "default"),
        dnscap_log_root=raw.get("dnscap_log_root"),
        threatsucker_config_set=raw.get("threatsucker_config_set"),
        include_demo_threat_intel=bool(raw.get("include_demo_threat_intel", False)),
        expected_findings=[str(item) for item in raw.get("expected_findings", [])],
        module_tests={str(key): str(value) for key, value in (raw.get("module_tests") or {}).items()},
        actionable_evidence=[str(item) for item in raw.get("actionable_evidence", [])],
        background_evidence=[str(item) for item in raw.get("background_evidence", [])],
    )


def save_scenario(scenario: Scenario) -> Path:
    SCENARIO_DIR.mkdir(parents=True, exist_ok=True)
    path = _scenario_path(scenario.name)
    data: dict[str, Any] = {
        "name": scenario.name,
        "description": scenario.description,
        "mode": scenario.mode,
        "prompt_profile": scenario.prompt_profile,
        "dnscap_log_root": scenario.dnscap_log_root,
        "threatsucker_config_set": scenario.threatsucker_config_set,
        "include_demo_threat_intel": scenario.include_demo_threat_intel,
        "expected_findings": scenario.expected_findings,
        "module_tests": scenario.module_tests,
        "actionable_evidence": scenario.actionable_evidence,
        "background_evidence": scenario.background_evidence,
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def validate_scenario(scenario: Scenario) -> list[str]:
    warnings: list[str] = []
    if scenario.mode not in {"demo", "live"}:
        warnings.append("Scenario mode must be either 'demo' or 'live'.")
    if scenario.mode == "live" and scenario.include_demo_threat_intel:
        warnings.append("Live scenario explicitly includes demo ThreatSucker intel.")
    if scenario.mode == "live" and scenario.dnscap_log_root and "imported_logs" in scenario.dnscap_log_root:
        warnings.append("Live scenario points at the bundled imported demo DNS logs.")
    if not scenario.prompt_profile:
        warnings.append("Scenario has no prompt profile.")
    detected_modules = {path.name for path in (PROJECT_ROOT / "modules").iterdir() if path.is_dir()}
    for module_name in scenario.module_tests:
        if module_name not in detected_modules:
            warnings.append(f"Scenario references unknown module: {module_name}.")
    return warnings
