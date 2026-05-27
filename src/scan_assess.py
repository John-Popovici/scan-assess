from __future__ import annotations

import argparse
import json
import os
import platform
import socket
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from src.runners.run_modules import run_modules
from src.llm_profiles import LlmProfile, load_llm_profile
from src.module_config import load_module_runtime_config, write_module_runtime_config
from src.prompt_profiles import PromptProfile, load_prompt_profile
from src.scenarios import Scenario, load_scenario

from openai import OpenAI


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_ROOT = PROJECT_ROOT / "modules"
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
REPORTS_ROOT = PROJECT_ROOT / "reports"
DEMO_DNSCAP_LOG_ROOT = MODULES_ROOT / "dnscap" / "imported_logs"
LOCAL_TZ = ZoneInfo("Europe/Luxembourg")


def run_machine_info() -> dict[str, str]:
    hostname = socket.gethostname()
    return {
        "hostname": hostname,
        "platform_node": platform.node() or hostname,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }


def european_time_label(ts: datetime) -> str:
    return ts.astimezone(LOCAL_TZ).strftime("%d/%m/%Y %H:%M:%S %Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run scan-assess modules and generate a local LLM security report.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--demo",
        action="store_true",
        help="Run the bundled phishing-DNS demo scenario with demo ThreatSucker intel enabled.",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="Run the normal official path. This is the default when --demo is not supplied.",
    )
    parser.add_argument(
        "--dnscap-log-root",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dnscap-period",
        choices=["day", "week", "month", "year", "forever", "custom", "since_last_run"],
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dnscap-start",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dnscap-end",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--threatsucker-config-set",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--include-demo-threat-intel",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--prompt-profile",
        default=None,
        help="Prompt profile name from config/prompt_profiles.",
    )
    parser.add_argument(
        "--llm-profile",
        default=None,
        help="LLM profile name from config/llm_profiles.",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Scenario pack name from config/scenarios. Scenario defaults can still be overridden by explicit CLI options.",
    )
    parser.add_argument(
        "--prompt-dev-evidence",
        type=Path,
        help="JSON file containing editable Prompt Developer evidence. When supplied, modules are not executed.",
    )
    return parser.parse_args()


def _project_path(raw_path: str | Path | None) -> Path | None:
    if raw_path in (None, ""):
        return None
    path = Path(raw_path)
    return path if path.is_absolute() else PROJECT_ROOT / path


def apply_scenario_defaults(args: argparse.Namespace) -> tuple[Scenario | None, list[str]]:
    scenario = load_scenario(args.scenario) if args.scenario else None
    notes: list[str] = []
    if scenario is None:
        return None, notes

    notes.append(f"scenario: {scenario.name}")
    notes.append(f"scenario description: {scenario.description}")

    if not args.demo and not args.live:
        args.demo = scenario.mode == "demo"
        args.live = scenario.mode == "live"
    if args.dnscap_log_root is None:
        args.dnscap_log_root = _project_path(scenario.dnscap_log_root)
    if not args.threatsucker_config_set:
        args.threatsucker_config_set = scenario.threatsucker_config_set
    if not args.prompt_profile:
        args.prompt_profile = scenario.prompt_profile
    if scenario.include_demo_threat_intel:
        args.include_demo_threat_intel = True
    if scenario.expected_findings:
        notes.append(f"scenario expected findings: {', '.join(scenario.expected_findings)}")
    return scenario, notes


def configure_run_mode(args: argparse.Namespace) -> tuple[list[str], PromptProfile, LlmProfile, Scenario | None]:
    """Set runner environment for the requested run path and return report notes."""
    scenario, notes = apply_scenario_defaults(args)
    prompt_profile = load_prompt_profile(args.prompt_profile)
    llm_profile = load_llm_profile(args.llm_profile)
    dnscap_module_dir = MODULES_ROOT / "dnscap"
    threatsucker_module_dir = MODULES_ROOT / "threatsucker"
    dnscap_config = load_module_runtime_config(dnscap_module_dir)
    threatsucker_config = load_module_runtime_config(threatsucker_module_dir)

    dnscap_updates: dict[str, str | None] = {}
    if args.dnscap_period:
        dnscap_updates["period"] = args.dnscap_period
    if args.dnscap_start:
        dnscap_updates["start"] = args.dnscap_start
    if args.dnscap_end:
        dnscap_updates["end"] = args.dnscap_end
    notes.append(f"prompt profile: {prompt_profile.name}")
    notes.append(f"LLM profile: {llm_profile.name}")
    notes.append(f"LLM model: {llm_profile.model}")
    notes.append(f"LLM base URL: {llm_profile.base_url}")
    notes.append(f"LLM context size: {llm_profile.context_size}")
    enabled_modules = os.environ.get("SCAN_ASSESS_ENABLED_MODULES", "").strip()
    notes.append(f"enabled modules: {enabled_modules if enabled_modules else 'all detected modules'}")

    demo_threat_intel = args.demo or args.include_demo_threat_intel

    if args.demo:
        dnscap_updates["log_root"] = str(args.dnscap_log_root or DEMO_DNSCAP_LOG_ROOT)
        threatsucker_config["include_demo_threat_intel"] = True
        threatsucker_config.setdefault("config_set", "default")
        notes.append("scan-assess mode: demo")
        notes.append(f"demo DNScap log root: {dnscap_updates['log_root']}")
        notes.append("demo ThreatSucker threat intel: enabled")
    else:
        if args.dnscap_log_root:
            dnscap_updates["log_root"] = str(args.dnscap_log_root)
            notes.append(f"DNScap log root: {args.dnscap_log_root}")
        threatsucker_config["include_demo_threat_intel"] = demo_threat_intel
        notes.append("scan-assess mode: live")
        notes.append(f"demo ThreatSucker threat intel: {'enabled' if demo_threat_intel else 'disabled'}")

    if args.threatsucker_config_set:
        threatsucker_config["config_set"] = args.threatsucker_config_set
        notes.append(f"ThreatSucker config set: {args.threatsucker_config_set}")
    elif threatsucker_config.get("config_set"):
        notes.append(f"ThreatSucker config set: {threatsucker_config['config_set']}")

    if dnscap_updates:
        dnscap_config.update(dnscap_updates)
        write_module_runtime_config(dnscap_module_dir, dnscap_config)
    write_module_runtime_config(threatsucker_module_dir, threatsucker_config)

    dnscap_config = load_module_runtime_config(dnscap_module_dir)
    dnscap_period = str(dnscap_config.get("period") or "forever")
    notes.append(f"DNScap import period: {dnscap_period}")
    if dnscap_config.get("start"):
        notes.append(f"DNScap import start: {dnscap_config['start']}")
    if dnscap_config.get("end"):
        notes.append(f"DNScap import end: {dnscap_config['end']}")
    if dnscap_config.get("log_root"):
        notes.append(f"DNScap log root: {dnscap_config['log_root']}")

    return notes, prompt_profile, llm_profile, scenario


def create_run_dirs(ts: datetime) -> tuple[Path, Path]:
    """Create output and report directories for the current run based on the timestamp."""
    date_path = Path(ts.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '-'))

    output_dir = OUTPUTS_ROOT / date_path
    report_dir = REPORTS_ROOT

    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return output_dir, report_dir


def collect_json_payload(
    json_files: list[Path], root_for_names: Path
) -> list[dict[str, str]]:
    return [
        {
            "filename": str(json_file.relative_to(root_for_names)),
            "file_data": json_file.read_text(encoding="utf-8"),
        }
        for json_file in json_files
    ]


def collect_prompt_developer_payload(evidence_path: Path, output_dir: Path) -> list[dict[str, str]]:
    raw = json.loads(evidence_path.read_text(encoding="utf-8"))
    raw_files = raw.get("files", []) if isinstance(raw, dict) else raw
    if not isinstance(raw_files, list):
        raise ValueError("Prompt Developer evidence must be a list or an object with a 'files' list.")

    payload_files: list[dict[str, str]] = []
    for index, item in enumerate(raw_files, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Prompt Developer evidence item {index} must be an object.")
        filename = str(item.get("filename") or f"prompt_developer/evidence_{index}.json")
        file_data = item.get("file_data", item.get("data", {}))
        file_text = file_data if isinstance(file_data, str) else json.dumps(file_data, indent=2, sort_keys=True)
        target = output_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file_text, encoding="utf-8")
        payload_files.append({"filename": filename, "file_data": file_text})
    return payload_files


def analyze_with_llm(files: list[dict[str, str]], prompt_profile: PromptProfile, llm_profile: LlmProfile) -> str:
    if not files:
        return "No data files were generated by modules for this run."
    
    sections = [f"File: {f['filename']}\n{f['file_data']}" for f in files]
    module_prompt: str = "\n\n".join(sections)

    print("Analyzing with LLM...")
    client = OpenAI(
        api_key=llm_profile.resolved_api_key() or "not-needed",
        base_url=llm_profile.base_url,
    )

    response = client.chat.completions.create(
        model=llm_profile.model,
        messages=[
            {"role": "system", "content": prompt_profile.system_prompt},
            {
                "role": "user",
                "content": f"{prompt_profile.user_prompt}\n\n{module_prompt}",
            },
        ],
    )

    return response.choices[0].message.content or ""


def save_report(
    ts: datetime,
    report_dir: Path,
    report_body: str,
    files: list[dict[str, str]],
    info: list[str],
    machine_info: dict[str, str],
) -> Path:
    print("Writing report...")

    report_path = (
        report_dir / f"security_report_{ts.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '-')}.md"
    )

    header_lines = [
        "# Security Analysis Report\n",
        f"Generated (Europe/Luxembourg): {european_time_label(ts)}",
        f"Generated (UTC): {ts.isoformat()}",
    ]

    # List the parameters and provenance for the run before the LLM summary.
    header_lines.extend(["", "## Run Parameters and Provenance"])
    header_lines.append(f"- run machine: {machine_info.get('hostname', 'unknown')}")
    header_lines.append(f"- run platform: {machine_info.get('platform', 'unknown')}")
    if info:
        header_lines.extend([f"- {item}" for item in info])
    else:
        header_lines.append("- No modules executed or no files generated.")

    # List files that were included in the analysis
    header_lines.extend(["", "## Input Files"])
    if files:
        header_lines.extend([f"- {item['filename']}" for item in files])
    else:
        header_lines.append("- None")

    # Append the main report body generated by the LLM
    header_lines.extend(["", report_body.strip(), ""])
    report_path.write_text("\n".join(header_lines), encoding="utf-8")

    return report_path


def save_run_manifest(
    ts: datetime,
    output_dir: Path,
    report_path: Path,
    prompt_profile: PromptProfile,
    llm_profile: LlmProfile,
    scenario: Scenario | None,
    files: list[dict[str, str]],
    info: list[str],
    machine_info: dict[str, str],
) -> Path:
    manifest_path = output_dir / "run_manifest.json"
    enabled_modules = os.environ.get("SCAN_ASSESS_ENABLED_MODULES", "").strip()
    dnscap_config = load_module_runtime_config(MODULES_ROOT / "dnscap")
    threatsucker_config = load_module_runtime_config(MODULES_ROOT / "threatsucker")
    manifest = {
        "report_path": str(report_path),
        "generated_at_utc": ts.isoformat(),
        "generated_at_local": european_time_label(ts),
        "timezone": "Europe/Luxembourg",
        "run_purpose": os.environ.get("SCAN_ASSESS_RUN_PURPOSE", "assessment"),
        "prompt_profile": prompt_profile.name,
        "llm_profile": llm_profile.name,
        "llm_model": llm_profile.model,
        "llm_base_url": llm_profile.base_url,
        "llm_context_size": llm_profile.context_size,
        "scenario": scenario.name if scenario else None,
        "enabled_modules": [item for item in enabled_modules.split(",") if item] if enabled_modules else "all detected modules",
        "dnscap_import": {
            "log_root": dnscap_config.get("log_root"),
            "period": dnscap_config.get("period", "forever"),
            "start": dnscap_config.get("start"),
            "end": dnscap_config.get("end"),
        },
        "threatsucker_config": {
            "config_set": threatsucker_config.get("config_set"),
            "include_demo_threat_intel": threatsucker_config.get("include_demo_threat_intel"),
        },
        "run_machine": machine_info,
        "module_runner_information": info,
        "input_files": [item["filename"] for item in files],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def main() -> None:
    args = parse_args()
    run_notes, prompt_profile, llm_profile, scenario = configure_run_mode(args)
    machine_info = run_machine_info()
    ts = datetime.now(UTC)
    output_dir, report_dir = create_run_dirs(ts) # Create output and report directories

    if args.prompt_dev_evidence:
        payload_files = collect_prompt_developer_payload(args.prompt_dev_evidence, output_dir)
        runner_info = [
            "run purpose: validation",
            f"prompt developer evidence payload: {args.prompt_dev_evidence}",
        ]
    else:
        generated_json_files, runner_info, runner_errors = run_modules(MODULES_ROOT, output_dir)
        if runner_errors:
            print("\nModule Runner Errors:")
            for error in runner_errors:
                print(f"- {error}")
            print("Stopping execution due to module runner errors.")
            return
        payload_files = collect_json_payload(generated_json_files, output_dir)
    report_body = analyze_with_llm(payload_files, prompt_profile, llm_profile)
    report_path = save_report(ts, report_dir, report_body, payload_files, [*run_notes, *runner_info], machine_info)
    manifest_path = save_run_manifest(ts, output_dir, report_path, prompt_profile, llm_profile, scenario, payload_files, [*run_notes, *runner_info], machine_info)

    print(f"\nReport saved to: {report_path}")
    print(f"Run manifest saved to: {manifest_path}")


if __name__ == "__main__":
    main()
