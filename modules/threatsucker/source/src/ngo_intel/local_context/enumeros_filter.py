from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ngo_intel.io_utils import stable_hash, write_csv, write_jsonl
from ngo_intel.local_context.importers import load_json_document
from ngo_intel.paths import ProjectPaths


def filter_enumeros_documents(paths: list[str | Path], out_dir: str | Path | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in _expand_json_paths(paths):
        data = load_json_document(path)
        findings.extend(filter_enumeros_document(data, str(path)))

    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        write_jsonl(out_path / "enumeros_findings.jsonl", findings)
        write_csv(out_path / "enumeros_findings.csv", findings)
        (out_path / "enumeros_findings.md").write_text(render_enumeros_findings(findings), encoding="utf-8")
    return findings


def filter_enumeros_document(data: dict[str, Any], evidence_path: str | None = None) -> list[dict[str, Any]]:
    hostname = str(data.get("hostname") or "unknown-host")
    findings: list[dict[str, Any]] = []
    findings.extend(_version_status_findings(hostname, data, evidence_path))
    findings.extend(_browser_inventory_findings(hostname, data, evidence_path))
    findings.extend(_network_findings(hostname, data, evidence_path))
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    if summary.get("overall") in {"warnings", "review"}:
        findings.append(
            _finding(
                hostname,
                "summary",
                "enumeros_summary",
                f"Enumeros overall status is {summary.get('overall')}",
                "review",
                evidence_path,
                {"summary": summary},
            )
        )
    return findings


def run_enumeros_binary(binary: str | Path, paths: ProjectPaths, save_name: str | None = None) -> Path:
    """Run Enumeros locally and save its JSON output for repeatable filtering.

    This is optional. Most NGO workflows can collect JSON on another platform and
    import/filter it later with no live execution.
    """
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=180)
    data = json.loads(result.stdout)
    out_dir = paths.local_context_dir / "imported" / "enumeros"
    out_dir.mkdir(parents=True, exist_ok=True)
    name = save_name or f"enumeros_{data.get('hostname', 'host')}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path = out_dir / name
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out_path


def _version_status_findings(hostname: str, data: dict[str, Any], evidence_path: str | None) -> list[dict[str, Any]]:
    version_status = data.get("version_status") if isinstance(data.get("version_status"), dict) else {}
    items = version_status.get("items", [])
    findings: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return findings
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", ""))
        name = str(item.get("name", "unknown"))
        if status == "outdated":
            findings.append(
                _finding(
                    hostname,
                    "outdated_software",
                    name,
                    f"{name} is outdated: installed {item.get('installed')} latest {item.get('latest')}",
                    "high" if name == "os" else "review",
                    evidence_path,
                    item,
                )
            )
        elif status == "unknown":
            findings.append(
                _finding(hostname, "unknown_version_status", name, f"{name} version status is unknown", "info", evidence_path, item)
            )
    return findings


def _browser_inventory_findings(hostname: str, data: dict[str, Any], evidence_path: str | None) -> list[dict[str, Any]]:
    browsers = data.get("browsers") if isinstance(data.get("browsers"), dict) else {}
    findings: list[dict[str, Any]] = []
    for browser, version in browsers.items():
        if version not in (None, "", "null"):
            findings.append(
                _finding(
                    hostname,
                    "browser_detected",
                    str(browser),
                    f"{browser} detected at version {version}",
                    "info",
                    evidence_path,
                    {"browser": browser, "version": version},
                )
            )
    return findings


def _network_findings(hostname: str, data: dict[str, Any], evidence_path: str | None) -> list[dict[str, Any]]:
    network = data.get("network_discovery") if isinstance(data.get("network_discovery"), dict) else {}
    findings: list[dict[str, Any]] = []
    for host in network.get("hosts", []) if isinstance(network.get("hosts"), list) else []:
        ip = str(host.get("ip", ""))
        for port_item in host.get("open_ports", []) if isinstance(host.get("open_ports"), list) else []:
            port = str(port_item.get("port", port_item)) if isinstance(port_item, dict) else str(port_item)
            findings.append(
                _finding(
                    hostname,
                    "open_port",
                    port,
                    f"Enumeros observed open TCP port {port} on {ip}",
                    _port_severity(port),
                    evidence_path,
                    {"ip": ip, "port": port, "status": port_item.get("status", "open") if isinstance(port_item, dict) else "open"},
                )
            )
    return findings


def render_enumeros_findings(findings: list[dict[str, Any]]) -> str:
    lines = [
        "# Enumeros Filtered Findings",
        "",
        "Filtered host facts from stored or live Enumeros JSON. These are context items for an AI, not standalone risk decisions.",
        "",
    ]
    if not findings:
        lines.append("No notable Enumeros findings were produced.")
        return "\n".join(lines) + "\n"
    for item in findings:
        lines.extend(
            [
                f"## {item['title']}",
                "",
                f"- Host: {item['host']}",
                f"- Kind: {item['kind']}",
                f"- Severity hint: {item['severity_hint']}",
                f"- Evidence: {item.get('evidence_path') or 'enumeros json'}",
                "",
            ]
        )
    return "\n".join(lines)


def _finding(
    host: str,
    kind: str,
    subject: str,
    title: str,
    severity_hint: str,
    evidence_path: str | None,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "finding_id": stable_hash(f"enumeros:{host}:{kind}:{subject}:{json.dumps(evidence, sort_keys=True)}"),
        "host": host,
        "kind": kind,
        "subject": subject,
        "title": title,
        "severity_hint": severity_hint,
        "evidence_path": evidence_path,
        "evidence": evidence,
        "suggested_ai_use": "Use as host context when deciding whether a broad Luxembourg NGO threat is locally relevant.",
    }


def _port_severity(port: str) -> str:
    if port in {"23", "135", "139", "445", "3389", "5900", "5985", "5986"}:
        return "high"
    if port in {"22", "80", "443", "8080", "8443", "631", "9100"}:
        return "review"
    return "info"


def _expand_json_paths(paths: list[str | Path]) -> list[Path]:
    expanded: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.json")))
        elif path.exists():
            expanded.append(path)
    return expanded
