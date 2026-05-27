"""scan-assess runner for the vendored ThreatSucker correlation pipeline."""

from __future__ import annotations

import csv
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from src.runners.base_runner import BaseRunner
from src.module_config import load_module_runtime_config


DNS_HEADERS = [
    "timestamp",
    "host",
    "queried_domain",
    "query_type",
    "source",
    "os",
    "interface",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
]


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def _dnscap_summary_to_rows(path: Path) -> list[dict[str, str]]:
    data = _load_json(path)
    if not data:
        return []
    rows: list[dict[str, str]] = []
    for event in data.get("events", []) if isinstance(data.get("events"), list) else []:
        if not isinstance(event, dict) or not event.get("qname"):
            continue
        rows.append(
            {
                "timestamp": str(event.get("ts", "")),
                "host": str(event.get("host", "")),
                "queried_domain": str(event.get("qname", "")).strip().lower().rstrip("."),
                "query_type": str(event.get("qtype", "")),
                "source": "scan-assess-dnscap",
                "os": str(event.get("os", "")),
                "interface": str(event.get("interface", "")),
                "src_ip": str(event.get("src_ip", "")),
                "dst_ip": str(event.get("dst_ip", "")),
                "src_port": str(event.get("src_port", "")),
                "dst_port": str(event.get("dst_port", "")),
                "proto": str(event.get("proto", "")),
            }
        )
    return rows


def _write_dns_context(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DNS_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow({header: row.get(header, "") for header in DNS_HEADERS})


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _copy_work_tree(source_root: Path, work_root: Path, include_demo_intel: bool = False) -> None:
    ignored_patterns = [
        ".git",
        ".venv",
        ".pytest_cache",
        "__pycache__",
        "*.pyc",
        ".DS_Store",
        "data/normalized",
        "data/scored",
        "data/agent_context",
        "data/mini",
        "local_context/imported",
    ]
    if not include_demo_intel:
        ignored_patterns.extend(
            [
                "critical_dns_match_campaign.json",
                "demo_invoice_fraud_event.json",
                "local_misp_dns_hit.json",
                "misp_event_sample.json",
                "phishtank_lookup_sample.json",
                "urlhaus_sample.jsonl",
                "vulnerability_lookup_sample.jsonl",
            ]
        )
    ignore = shutil.ignore_patterns(*ignored_patterns)
    shutil.copytree(source_root, work_root, ignore=ignore)


class Runner(BaseRunner):
    """Run ThreatSucker's explainable threat-intel correlation pipeline."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        config = load_module_runtime_config(module_dir)
        source_root = module_dir / "source"
        work_root = output_dir / "workspace"
        include_demo_raw = config.get("include_demo_threat_intel", os.environ.get("SCAN_ASSESS_INCLUDE_DEMO_THREAT_INTEL", ""))
        include_demo_intel = str(include_demo_raw).strip().lower() in {"1", "true", "yes"}
        _copy_work_tree(source_root, work_root, include_demo_intel=include_demo_intel)

        package_root = work_root / "src"
        if str(package_root) not in sys.path:
            sys.path.insert(0, str(package_root))

        from ngo_intel.agent_brief import generate_agent_context
        from ngo_intel.config_sets import apply_config_set, ensure_default_config_set
        from ngo_intel.local_context.importers import import_enumeros_json, import_safesniff_json
        from ngo_intel.normalize import normalize_all
        from ngo_intel.paths import ProjectPaths
        from ngo_intel.scoring import score_all

        run_root = output_dir.parent
        paths = ProjectPaths.discover(work_root)
        ensure_default_config_set(paths)
        config_set = str(config.get("config_set") or os.environ.get("SCAN_ASSESS_THREATSUCKER_CONFIG_SET", "")).strip()
        if config_set:
            apply_config_set(paths, config_set)

        dnscap_path = run_root / "dnscap" / "dnscap_summary.json"
        enumeros_path = run_root / "enumeros" / "enumeros.json"
        safesniff_path = run_root / "safesniff" / "safesniff.json"

        imported: dict[str, Any] = {}
        dns_rows = _dnscap_summary_to_rows(dnscap_path)
        _write_dns_context(paths.local_context_dir / "dns" / "current" / "queries.csv", dns_rows)
        imported["dnscap_dns_rows"] = len(dns_rows)

        if enumeros_path.exists():
            imported["enumeros"] = import_enumeros_json(paths, enumeros_path, append=False)
        if safesniff_path.exists():
            imported["safesniff"] = import_safesniff_json(paths, safesniff_path, append=True)

        normalized_indicators, normalized_vulns = normalize_all(paths)
        scored_indicators, scored_vulns = score_all(paths)
        generate_agent_context(paths)

        scored_dir = paths.scored_date_dir()
        agent_dir = paths.agent_context_dir / "current"
        relevant_indicators = _read_jsonl(scored_dir / "relevant_indicators.jsonl")
        relevant_vulnerabilities = _read_jsonl(scored_dir / "relevant_vulnerabilities.jsonl")
        top_threats = json.loads((agent_dir / "top_threats.json").read_text(encoding="utf-8"))
        dns_matches = [
            item for item in relevant_indicators
            if any(str(match).startswith("dns:") for match in item.get("matched_local_data", []))
        ]

        critical_items = [
            item for item in relevant_indicators
            if item.get("priority") == "critical" or int(item.get("score", 0)) >= 90
        ]
        high_or_critical = [
            item for item in relevant_indicators
            if item.get("priority") in {"critical", "high"} or int(item.get("score", 0)) >= 70
        ]
        critical_vulnerabilities = [
            item for item in relevant_vulnerabilities
            if item.get("priority") == "critical" or int(item.get("score", 0)) >= 90
        ]
        high_or_critical_vulnerabilities = [
            item for item in relevant_vulnerabilities
            if item.get("priority") in {"critical", "high"} or int(item.get("score", 0)) >= 70
        ]

        result = {
            "tool": "threatsucker",
            "mode": "explainable_threat_intel_correlation",
            "provenance": {
                "data_origin": "derived",
                "collection_method": "threat_intel_scoring_against_scan_assess_outputs",
                "config_set": config_set or "active_source_config",
                "demo_threat_intel_included": include_demo_intel,
                "live_collection": False,
                "sample_data": False,
                "note": "ThreatSucker correlates feed indicators against module outputs; raw module outputs remain available separately to the LLM.",
            },
            "imported_local_evidence": imported,
            "counts": {
                "normalized_indicators": len(normalized_indicators),
                "normalized_vulnerabilities": len(normalized_vulns),
                "scored_indicators": len(scored_indicators),
                "scored_vulnerabilities": len(scored_vulns),
                "relevant_indicators": len(relevant_indicators),
                "relevant_vulnerabilities": len(relevant_vulnerabilities),
                "dns_matches": len(dns_matches),
                "critical_items": len(critical_items),
                "high_or_critical_items": len(high_or_critical),
                "critical_vulnerabilities": len(critical_vulnerabilities),
                "high_or_critical_vulnerabilities": len(high_or_critical_vulnerabilities),
            },
            "critical_items": critical_items[:10],
            "critical_vulnerabilities": critical_vulnerabilities[:10],
            "relevant_vulnerabilities": relevant_vulnerabilities[:20],
            "top_threats": top_threats[:10],
            "dns_matches": dns_matches[:20],
            "outputs": {
                "intel_brief_md": str(agent_dir / "intel_brief.md"),
                "top_threats_json": str(agent_dir / "top_threats.json"),
                "relevant_indicators_jsonl": str(scored_dir / "relevant_indicators.jsonl"),
                "dns_matches_csv": str(scored_dir / "dns_matches.csv"),
            },
        }

        output_path = output_dir / "threatsucker_correlation.json"
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
