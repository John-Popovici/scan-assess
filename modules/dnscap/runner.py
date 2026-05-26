"""scan-assess runner for DNScap JSONL/CSV logs."""

from __future__ import annotations

import csv
import json
import os
from collections import Counter
from pathlib import Path

from src.runners.base_runner import BaseRunner


DNS_FIELDS = {
    "ts",
    "host",
    "os",
    "interface",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "qname",
    "qtype",
}


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _discover_dns_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    patterns = ["dns.jsonl", "dns.csv", "*.dns.jsonl", "*.dns.csv"]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(root.rglob(pattern))
    return sorted(set(files))


def _load_dns_events(files: list[Path]) -> list[dict]:
    events: list[dict] = []
    for path in files:
        if path.suffix == ".jsonl":
            events.extend(_read_jsonl(path))
        elif path.suffix == ".csv":
            events.extend(_read_csv(path))
    return [event for event in events if DNS_FIELDS.intersection(event)]


def _summary(events: list[dict], files: list[Path], root: Path, module_dir: Path) -> dict:
    qnames = Counter(str(event.get("qname", "")).lower() for event in events if event.get("qname"))
    qtypes = Counter(str(event.get("qtype", "")).upper() for event in events if event.get("qtype"))
    hosts = Counter(str(event.get("host", "")) for event in events if event.get("host"))
    sample_root = module_dir / "sample_logs"
    data_origin = "sample" if root.resolve() == sample_root.resolve() else "imported"

    return {
        "tool": "dnscap",
        "mode": "dns_log_import",
        "provenance": {
            "data_origin": data_origin,
            "collection_method": "log_import",
            "live_collection": False,
            "source_root": str(root),
            "sample_data": data_origin == "sample",
            "note": (
                "Bundled sample DNScap logs for parser/report testing; do not treat as live user activity."
                if data_origin == "sample"
                else "Imported DNScap logs; treat as historical DNS observation evidence, not proof of compromise."
            ),
        },
        "source_root": str(root),
        "input_files": [str(path.relative_to(root)) if path.is_relative_to(root) else str(path) for path in files],
        "summary": {
            "dns_event_count": len(events),
            "unique_qname_count": len(qnames),
            "unique_host_count": len(hosts),
            "top_qnames": [{"qname": name, "count": count} for name, count in qnames.most_common(10)],
            "qtypes": dict(qtypes),
            "hosts": dict(hosts),
        },
        "events": events[:100],
        "truncated": len(events) > 100,
    }


class Runner(BaseRunner):
    """Read DNScap logs and emit a compact JSON summary."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        log_root = Path(os.environ.get("SCAN_ASSESS_DNSCAP_LOG_ROOT", module_dir / "sample_logs"))
        if not log_root.exists():
            raise FileNotFoundError(f"DNScap log root not found: {log_root}")

        dns_files = _discover_dns_files(log_root)
        events = _load_dns_events(dns_files)
        data = _summary(events, dns_files, log_root, module_dir)

        output_path = output_dir / "dnscap_summary.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return True, [output_path]
