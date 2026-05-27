"""scan-assess runner for DNScap JSONL/CSV logs."""

from __future__ import annotations

import csv
import json
import platform
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.runners.base_runner import BaseRunner
from src.module_config import load_module_runtime_config, write_module_runtime_config


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

PERIOD_ALIASES = {
    "": "all",
    "all": "all",
    "forever": "all",
    "everything": "all",
    "day": "last_day",
    "last_day": "last_day",
    "week": "last_week",
    "last_week": "last_week",
    "month": "last_month",
    "last_month": "last_month",
    "year": "last_year",
    "last_year": "last_year",
    "since_last_run": "since_last_scan",
    "since_last_scan": "since_last_scan",
    "custom": "custom",
    "range": "custom",
    "time_period": "custom",
}

COLLECTOR_BINARY_BY_PLATFORM = {
    ("darwin", "arm64"): "dnslog-agent-aarch64-apple-darwin",
    ("darwin", "aarch64"): "dnslog-agent-aarch64-apple-darwin",
    ("darwin", "x86_64"): "dnslog-agent-x86_64-apple-darwin",
    ("linux", "aarch64"): "dnslog-agent-aarch64-unknown-linux-gnu",
    ("linux", "arm64"): "dnslog-agent-aarch64-unknown-linux-gnu",
    ("linux", "x86_64"): "dnslog-agent-x86_64-unknown-linux-gnu",
    ("windows", "amd64"): "dnslog-agent-x86_64-pc-windows-gnu.exe",
    ("windows", "x86_64"): "dnslog-agent-x86_64-pc-windows-gnu.exe",
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


def _parse_event_time(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_window_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _config_value(config: dict, key: str, default: str | None = None) -> str | None:
    value = config.get(key)
    if value not in (None, ""):
        return str(value)
    return default


def _normalise_period(value: object) -> str:
    return PERIOD_ALIASES.get(str(value or "all").strip().lower(), "all")


def _import_window(config: dict) -> tuple[str, datetime | None, datetime | None]:
    period = _normalise_period(config.get("period"))
    end = _parse_window_time(_config_value(config, "end")) or datetime.now(UTC)
    start = _parse_window_time(_config_value(config, "start"))

    if period == "since_last_scan":
        start = _parse_window_time(str(config.get("last_run_utc") or ""))
        if start is None:
            period = "all"
            end = None
    elif period == "last_day":
        start = start or end - timedelta(days=1)
    elif period == "last_week":
        start = start or end - timedelta(weeks=1)
    elif period == "last_month":
        start = start or end - timedelta(days=31)
    elif period == "last_year":
        start = start or end - timedelta(days=366)
    elif period == "custom":
        period = "custom"
    else:
        period = "all"
        start = None
        end = None

    return period, start, end


def _platform_key() -> tuple[str, str]:
    system = platform.system().strip().lower()
    machine = platform.machine().strip().lower()
    if system == "darwin":
        system = "darwin"
    elif system.startswith("win"):
        system = "windows"
    elif system == "linux":
        system = "linux"
    return system, machine


def _collector_binary_inventory(module_dir: Path, configured_binary: str | None = None) -> dict:
    bin_dir = module_dir / "bin"
    available = sorted(path for path in bin_dir.glob("dnslog-agent*") if path.is_file())
    configured_path: Path | None = None
    if configured_binary:
        raw_path = Path(configured_binary)
        configured_path = raw_path if raw_path.is_absolute() else module_dir / raw_path

    system, machine = _platform_key()
    expected_name = COLLECTOR_BINARY_BY_PLATFORM.get((system, machine))
    expected_path = bin_dir / expected_name if expected_name else None
    selected_path = configured_path or expected_path
    return {
        "role": "background_collector_binary_inventory",
        "current_platform": {"system": system, "machine": machine},
        "selected_binary": str(selected_path) if selected_path else None,
        "selected_binary_exists": bool(selected_path and selected_path.exists()),
        "selection_source": "configured" if configured_path else "platform_auto",
        "available_binaries": [path.name for path in available],
        "note": (
            "DNScap is a Rust background collector. scan-assess does not start packet capture; "
            "this Python runner imports the collector's stored JSONL/CSV logs for the configured time window."
        ),
    }


def _filter_events_by_window(events: list[dict], start: datetime | None, end: datetime | None) -> tuple[list[dict], int]:
    if start is None and end is None:
        return events, 0

    filtered: list[dict] = []
    missing_ts = 0
    for event in events:
        event_ts = _parse_event_time(event.get("ts"))
        if event_ts is None:
            missing_ts += 1
            continue
        if start is not None and event_ts < start:
            continue
        if end is not None and event_ts > end:
            continue
        filtered.append(event)
    return filtered, missing_ts


def _summary(
    events: list[dict],
    all_event_count: int,
    missing_ts_count: int,
    files: list[Path],
    root: Path,
    module_dir: Path,
    period: str,
    start: datetime | None,
    end: datetime | None,
) -> dict:
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
            "import_period": period,
            "window_start_utc": start.isoformat() if start else None,
            "window_end_utc": end.isoformat() if end else None,
            "last_run_marker_enabled": False,
            "sample_data": data_origin == "sample",
            "note": (
                "Bundled sample DNScap logs for parser/report testing; do not treat as live user activity."
                if data_origin == "sample"
                else "Imported DNScap logs; treat as historical DNS observation evidence, not proof of compromise."
            ),
        },
        "source_root": str(root),
        "collector": _collector_binary_inventory(module_dir),
        "import_window": {
            "period": period,
            "start_utc": start.isoformat() if start else None,
            "end_utc": end.isoformat() if end else None,
        },
        "input_files": [str(path.relative_to(root)) if path.is_relative_to(root) else str(path) for path in files],
        "summary": {
            "dns_event_count": len(events),
            "dns_event_count_before_window": all_event_count,
            "events_without_parseable_timestamp_excluded": missing_ts_count,
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
        config = load_module_runtime_config(module_dir)
        log_root = Path(_config_value(config, "log_root", "sample_logs") or "sample_logs")
        if not log_root.is_absolute():
            log_root = module_dir / log_root
        if not log_root.exists():
            raise FileNotFoundError(f"DNScap log root not found: {log_root}")

        dns_files = _discover_dns_files(log_root)
        all_events = _load_dns_events(dns_files)
        period, start, end = _import_window(config)
        events, missing_ts_count = _filter_events_by_window(all_events, start, end)
        data = _summary(events, len(all_events), missing_ts_count, dns_files, log_root, module_dir, period, start, end)
        marker_enabled = bool(config.get("update_last_run_marker", config.get("use_last_run_marker", False))) or period == "since_last_scan"
        data["provenance"]["last_run_marker_enabled"] = marker_enabled
        data["provenance"]["previous_last_run_utc"] = config.get("last_run_utc")
        data["collector"] = _collector_binary_inventory(module_dir, _config_value(config, "collector_binary"))

        output_path = output_dir / "dnscap_summary.json"
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        if marker_enabled:
            config["last_run_utc"] = datetime.now(UTC).isoformat()
            write_module_runtime_config(module_dir, config)
        return True, [output_path]
