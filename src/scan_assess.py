from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path
from src.runners.run_modules import run_modules

from openai import OpenAI


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_ROOT = PROJECT_ROOT / "modules"
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
REPORTS_ROOT = PROJECT_ROOT / "reports"
DEMO_DNSCAP_LOG_ROOT = MODULES_ROOT / "dnscap" / "imported_logs"

MODEL = "here"
SYSTEM_PROMPT = (
    "You are a concise cybersecurity analyst. "
    "Analyze the supplied files as the source of truth and make no other assumptions. "
    "Respect provenance metadata: sample or demo data is for testing only and must not produce security conclusions or action items. "
    "Imported logs are historical observations, not proof of compromise. "
    "Target-detection-only outputs are not service scans and must not be described as open-port findings. "
    "If SafeSniff output has mode='target_detection_only', provenance.active_network_scan=false, or total_tcp_connect_attempts_planned=0, state that no TCP service scan was run even if the selected profile name is 'thorough'. "
    "When DNS evidence contains lookalike, typo-squatted, login, password, invoice, payment, or document-sharing domains, classify the likely threat type such as phishing, credential theft, brand impersonation, or invoice fraud while stating that DNS logs alone do not prove compromise."
)
USER_PROMPT = (
    "Review the files and summarize what they contain. "
    "Triage the findings into a maximum of 5 actionable items to improve security in order of importance. "
    "This report should be understandable to a non technical user. "
    "If a file contains provenance.sample_data=true or provenance.data_origin='sample', mention it only as test data and exclude it from actionable items. "
    "When evidence is weak, say so plainly and do not invent risks. "
    "For suspicious DNS findings, name the suspicious domains, state the likely threat category, identify the affected host if present, and recommend concrete next steps such as checking browser history, warning the user, blocking the domains, and reviewing credentials. "
    "It must be in the following markdown format:\n"
    "## Summary\n"
    "- A brief summary of the overall findings.\n"
    "## Actionable Items\n"
    "- A numbered list of up to 5 actionable items, each with a brief explanation."
)

client = OpenAI(
    api_key="not-needed",
    base_url="http://localhost:8033/v1",
)


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
        help="Path to real DNScap dns.jsonl/dns.csv logs to import for this run.",
    )
    parser.add_argument(
        "--threatsucker-config-set",
        help="Named ThreatSucker config set to apply for this run.",
    )
    parser.add_argument(
        "--include-demo-threat-intel",
        action="store_true",
        help="Include bundled demo ThreatSucker feed items without switching DNScap to the demo log root.",
    )
    return parser.parse_args()


def configure_run_mode(args: argparse.Namespace) -> list[str]:
    """Set runner environment for the requested run path and return report notes."""
    notes: list[str] = []
    demo_threat_intel = args.demo or args.include_demo_threat_intel

    if args.demo:
        os.environ["SCAN_ASSESS_DNSCAP_LOG_ROOT"] = str(args.dnscap_log_root or DEMO_DNSCAP_LOG_ROOT)
        os.environ["SCAN_ASSESS_INCLUDE_DEMO_THREAT_INTEL"] = "true"
        os.environ.setdefault("SCAN_ASSESS_THREATSUCKER_CONFIG_SET", "default")
        notes.append("scan-assess mode: demo")
        notes.append(f"demo DNScap log root: {os.environ['SCAN_ASSESS_DNSCAP_LOG_ROOT']}")
        notes.append("demo ThreatSucker threat intel: enabled")
    else:
        if args.dnscap_log_root:
            os.environ["SCAN_ASSESS_DNSCAP_LOG_ROOT"] = str(args.dnscap_log_root)
            notes.append(f"DNScap log root: {args.dnscap_log_root}")
        elif args.live:
            os.environ.pop("SCAN_ASSESS_DNSCAP_LOG_ROOT", None)
        os.environ["SCAN_ASSESS_INCLUDE_DEMO_THREAT_INTEL"] = "true" if demo_threat_intel else "false"
        notes.append("scan-assess mode: live")
        notes.append(f"demo ThreatSucker threat intel: {'enabled' if demo_threat_intel else 'disabled'}")

    if args.threatsucker_config_set:
        os.environ["SCAN_ASSESS_THREATSUCKER_CONFIG_SET"] = args.threatsucker_config_set
        notes.append(f"ThreatSucker config set: {args.threatsucker_config_set}")
    elif os.environ.get("SCAN_ASSESS_THREATSUCKER_CONFIG_SET"):
        notes.append(f"ThreatSucker config set: {os.environ['SCAN_ASSESS_THREATSUCKER_CONFIG_SET']}")

    return notes


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


def analyze_with_llm(files: list[dict[str, str]]) -> str:
    if not files:
        return "No data files were generated by modules for this run."
    
    sections = [f"File: {f['filename']}\n{f['file_data']}" for f in files]
    module_prompt: str = "\n\n".join(sections)

    print("Analyzing with LLM...")

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"{USER_PROMPT}\n\n{module_prompt}",
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
) -> Path:
    print("Writing report...")

    report_path = (
        report_dir / f"security_report_{ts.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '-')}.md"
    )

    header_lines = [
        "# Security Analysis Report\n",
        f"Generated (UTC): {ts}",
    ]

    # List information about the module runs
    header_lines.extend(["", "## Module Runner Information"])
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


def main() -> None:
    args = parse_args()
    run_notes = configure_run_mode(args)
    ts = datetime.now(UTC)
    output_dir, report_dir = create_run_dirs(ts) # Create output and report directories

    generated_json_files, runner_info, runner_errors = run_modules(MODULES_ROOT, output_dir)
    if runner_errors:
        print("\nModule Runner Errors:")
        for error in runner_errors:
            print(f"- {error}")
        print("Stopping execution due to module runner errors.")
        return
    payload_files = collect_json_payload(generated_json_files, output_dir)
    report_body = analyze_with_llm(payload_files)
    report_path = save_report(ts, report_dir, report_body, payload_files, [*run_notes, *runner_info])

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
