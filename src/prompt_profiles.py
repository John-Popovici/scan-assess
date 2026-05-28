from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROMPT_PROFILE_DIR = PROJECT_ROOT / "config" / "prompt_profiles"


DEFAULT_SYSTEM_PROMPT = (
    "You are a careful cybersecurity analyst advising a small to medium Luxembourg-based NGO with 3 employees and an annual budget of about EUR 1.7m. "
    "Treat supplied module JSON as the source of truth and make no assumptions beyond that telemetry. "
    "Use the NGO context to prioritise practical, low-noise recommendations suitable for a small team with limited operational capacity, donor trust obligations, cloud-service dependence, and likely exposure to phishing, credential theft, invoice fraud, grant/payment fraud, and brand impersonation. "
    "Respect provenance metadata: sample or demo data is for testing only and must not produce security conclusions or action items. "
    "Imported logs are historical observations, not proof of compromise. "
    "Clearly distinguish local-host telemetry from network-observed or imported telemetry about other devices. "
    "When asset_context.device_scope or asset_context.is_local_host is present, use it to state whether a finding is on the scan-assess machine, an observed endpoint, or a network device. "
    "Target-detection-only outputs are not service scans and must not be described as open-port findings. "
    "If SafeSniff output has mode='target_detection_only', provenance.active_network_scan=false, or total_tcp_connect_attempts_planned=0, state that no TCP service scan was run even if the selected profile name is 'thorough'. "
    "When DNS telemetry contains lookalike, typo-squatted, login, password, invoice, payment, or document-sharing domains, classify the likely threat type such as phishing, credential theft, brand impersonation, or invoice fraud while stating that DNS logs alone do not prove compromise."
)

DEFAULT_USER_PROMPT = (
    "Review the files and summarize what they contain for a non-technical operator at a small Luxembourg NGO. "
    "Triage the findings into a maximum of 5 actionable items to improve security in order of importance. "
    "Prefer concrete, proportionate actions that a 3-person organisation can realistically complete or delegate. "
    "Make the potential business/mission impact clear, especially where telemetry suggests phishing, credential theft, invoice fraud, donor-data exposure, service disruption, or outdated internet-facing software. "
    "Cite the telemetry filename for every finding so the GUI can link the report back to JSON telemetry. "
    "For every affected host or device, state whether the telemetry is local to the scan-assess machine, imported inventory about another endpoint, DNS activity observed for another device, or a network device found by SafeSniff. "
    "Start every finding bullet with `Scope:` followed by one of `local scan-assess machine`, `imported endpoint inventory`, `observed DNS device`, `network-observed device`, or `unknown`. "
    "If a file contains provenance.sample_data=true or provenance.data_origin='sample', mention it only as test data and exclude it from actionable items. "
    "When telemetry is weak, say so plainly and do not invent risks. "
    "For suspicious DNS findings, name the suspicious domains, state the likely threat category, identify the affected host if present, and recommend concrete next steps such as checking browser history, warning the user, blocking the domains, reviewing credentials, and verifying related invoices or payment requests. "
    "Do not claim compromise from DNS telemetry alone. "
    "It must be in the following markdown format:\n"
    "## Summary\n"
    "- A brief summary of the overall findings.\n"
    "## Findings\n"
    "- Telemetry-backed observations with filenames.\n"
    "## Actionable Items\n"
    "- A numbered list of up to 5 actionable items, each with a brief explanation."
)


@dataclass(frozen=True)
class PromptProfile:
    name: str
    description: str
    system_prompt: str
    user_prompt: str
    tags: list[str]


def _profile_path(name: str) -> Path:
    safe_name = name.strip().replace("/", "-")
    return PROMPT_PROFILE_DIR / f"{safe_name}.yaml"


def default_profile() -> PromptProfile:
    return PromptProfile(
        name="default",
        description="Default NGO-focused scan-assess analyst prompt.",
        system_prompt=DEFAULT_SYSTEM_PROMPT,
        user_prompt=DEFAULT_USER_PROMPT,
        tags=["live", "ngo", "luxembourg", "default"],
    )


def list_prompt_profiles() -> list[str]:
    if not PROMPT_PROFILE_DIR.exists():
        return ["default"]
    names = sorted(path.stem for path in PROMPT_PROFILE_DIR.glob("*.yaml"))
    return names or ["default"]


def load_prompt_profile(name: str | None) -> PromptProfile:
    profile_name = name or "default"
    path = _profile_path(profile_name)
    if not path.exists():
        if profile_name == "default":
            return default_profile()
        raise FileNotFoundError(f"Prompt profile not found: {profile_name}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return PromptProfile(
        name=str(raw.get("name") or profile_name),
        description=str(raw.get("description") or ""),
        system_prompt=str(raw.get("system_prompt") or ""),
        user_prompt=str(raw.get("user_prompt") or ""),
        tags=[str(item) for item in raw.get("tags", [])],
    )


def save_prompt_profile(profile: PromptProfile) -> Path:
    PROMPT_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    path = _profile_path(profile.name)
    data: dict[str, Any] = {
        "name": profile.name,
        "description": profile.description,
        "tags": profile.tags,
        "system_prompt": profile.system_prompt,
        "user_prompt": profile.user_prompt,
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def validate_prompt_profile(profile: PromptProfile) -> list[str]:
    warnings: list[str] = []
    combined = f"{profile.system_prompt}\n{profile.user_prompt}".lower()
    required_signals = {
        "source-of-truth telemetry": ["source of truth", "supplied files", "supplied module json", "only supplied"],
        "provenance awareness": ["provenance"],
        "weak-telemetry caution": ["not proof", "do not prove", "do not invent", "weak"],
        "DNS threat classification": ["phishing", "credential", "dns"],
    }
    if "validation" not in profile.tags:
        required_signals["sample/demo handling"] = ["sample", "demo"]
    for label, needles in required_signals.items():
        if not any(needle in combined for needle in needles):
            warnings.append(f"Missing or weak guardrail: {label}.")
    if not profile.system_prompt.strip():
        warnings.append("System prompt is empty.")
    if not profile.user_prompt.strip():
        warnings.append("User prompt is empty.")
    return warnings
