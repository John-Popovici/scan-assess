from __future__ import annotations

import bz2
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from .config import load_source_config
from .io_utils import ensure_dir, write_jsonl
from .paths import ProjectPaths

USER_AGENT = "ThreatSucker/0.1 (+https://example.invalid/university-project; contact: local-demo)"


def collect_live_sources(paths: ProjectPaths, profile_id: str = "luxembourg_ngo") -> dict[str, Any]:
    """Fetch live public intel into data/raw.

    The collectors keep raw responses inspectable and intentionally small. They
    do not require credentials except for the optional PhishTank bulk feed.
    """
    config = load_source_config(paths.config_dir / "source_config.yaml").get("sources", {})
    summary: dict[str, Any] = {"profile": profile_id, "sources": {}}
    timeout = httpx.Timeout(30.0, connect=10.0)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        if config.get("urlhaus", {}).get("enabled", False):
            summary["sources"]["urlhaus"] = _safe_collect(lambda: collect_urlhaus(paths, config["urlhaus"], client))
        if config.get("misp_osint", {}).get("enabled", False):
            summary["sources"]["misp_osint"] = _safe_collect(lambda: collect_misp_osint(paths, config["misp_osint"], client))
        if config.get("circl_vulnerability_lookup", {}).get("enabled", False):
            summary["sources"]["circl_vulnerability_lookup"] = _safe_collect(lambda: collect_vulnerability_lookup(paths, config["circl_vulnerability_lookup"], client))
        if config.get("phishtank", {}).get("enabled", False):
            summary["sources"]["phishtank"] = _safe_collect(lambda: collect_phishtank(paths, config["phishtank"], client))
    write_jsonl(paths.data_dir / "state" / "live_collect_runs.jsonl", [summary])
    return summary


def _safe_collect(fn: Any) -> dict[str, Any]:
    try:
        return fn()
    except Exception as exc:  # Live feeds should fail soft so other sources can update.
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


def collect_urlhaus(paths: ProjectPaths, config: dict[str, Any], client: httpx.Client) -> dict[str, Any]:
    url = config.get("url", "https://urlhaus-api.abuse.ch/v1/urls/recent/")
    max_records = int(config.get("max_records", 200))
    response = client.get(url)
    response.raise_for_status()
    data = response.json()
    records = _records_from_urlhaus_response(data)[:max_records]
    out_dir = ensure_dir(paths.raw_source_date_dir("urlhaus"))
    raw_path = out_dir / "recent.json"
    jsonl_path = out_dir / "recent.jsonl"
    raw_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    write_jsonl(jsonl_path, records)
    return {"status": "ok", "records": len(records), "raw_path": str(raw_path), "jsonl_path": str(jsonl_path)}


def collect_misp_osint(paths: ProjectPaths, config: dict[str, Any], client: httpx.Client) -> dict[str, Any]:
    base_url = str(config.get("url", "https://www.circl.lu/doc/misp/feed-osint/")).rstrip("/") + "/"
    max_events = int(config.get("max_events", 20))
    manifest_response = client.get(f"{base_url}manifest.json")
    manifest_response.raise_for_status()
    manifest = manifest_response.json()
    event_ids = _misp_event_ids(manifest)[:max_events]
    out_dir = ensure_dir(paths.raw_source_date_dir("misp"))
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    fetched = 0
    for event_id in event_ids:
        event_response = client.get(f"{base_url}{event_id}.json")
        if event_response.status_code == 404:
            continue
        event_response.raise_for_status()
        (out_dir / f"{event_id}.json").write_text(event_response.text, encoding="utf-8")
        fetched += 1
    return {"status": "ok", "manifest_events": len(event_ids), "events_fetched": fetched, "raw_dir": str(out_dir)}


def collect_vulnerability_lookup(paths: ProjectPaths, config: dict[str, Any], client: httpx.Client) -> dict[str, Any]:
    url = config.get("url", "https://vulnerability.circl.lu/api/last")
    max_records = int(config.get("max_records", 30))
    response = client.get(url)
    response.raise_for_status()
    data = response.json()
    records = [_normalize_live_vulnerability_record(record) for record in _records_from_vulnerability_response(data)[:max_records]]
    out_dir = ensure_dir(paths.raw_source_date_dir("vulnerability_lookup"))
    raw_path = out_dir / "last.json"
    jsonl_path = out_dir / "last.jsonl"
    raw_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    write_jsonl(jsonl_path, records)
    return {"status": "ok", "records": len(records), "raw_path": str(raw_path), "jsonl_path": str(jsonl_path)}


def collect_phishtank(paths: ProjectPaths, config: dict[str, Any], client: httpx.Client) -> dict[str, Any]:
    app_key = os.getenv("PHISHTANK_APP_KEY")
    if not app_key:
        return {"status": "skipped", "reason": "PHISHTANK_APP_KEY not set"}
    max_records = int(config.get("max_records", 200))
    url = str(config.get("data_url_template", "")).format(app_key=app_key)
    response = client.get(url, headers={"Accept": "application/octet-stream", "User-Agent": USER_AGENT})
    response.raise_for_status()
    payload = bz2.decompress(response.content)
    records = json.loads(payload.decode("utf-8"))[:max_records]
    out_dir = ensure_dir(paths.raw_source_date_dir("phishtank"))
    raw_path = out_dir / "online-valid.json"
    raw_path.write_text(json.dumps({"results": records}, indent=2), encoding="utf-8")
    return {"status": "ok", "records": len(records), "raw_path": str(raw_path)}


def _records_from_urlhaus_response(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        keyed_records: list[dict[str, Any]] = []
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        keyed_records.append({"id": key, **item})
        if keyed_records:
            return keyed_records
        for key in ["urls", "payloads", "data"]:
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _misp_event_ids(manifest: Any) -> list[str]:
    if isinstance(manifest, dict):
        return [str(key) for key in manifest.keys() if key not in {"manifest", "version"}]
    if isinstance(manifest, list):
        ids: list[str] = []
        for item in manifest:
            if isinstance(item, str):
                ids.append(item.removesuffix(".json"))
            elif isinstance(item, dict):
                value = item.get("uuid") or item.get("id") or item.get("path")
                if value:
                    ids.append(str(value).removesuffix(".json"))
        return ids
    return []


def _records_from_vulnerability_response(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ["data", "vulnerabilities", "results", "items"]:
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
        return [data]
    return []


def _normalize_live_vulnerability_record(record: dict[str, Any]) -> dict[str, Any]:
    cve = str(record.get("id") or record.get("cve") or record.get("vuln_id") or record.get("cveMetadata", {}).get("cveId") or "unknown")
    containers = record.get("containers", {}) if isinstance(record.get("containers"), dict) else {}
    cna = containers.get("cna", {}) if isinstance(containers.get("cna"), dict) else {}
    descriptions = cna.get("descriptions", []) if isinstance(cna.get("descriptions"), list) else []
    description = ""
    if descriptions and isinstance(descriptions[0], dict):
        description = str(descriptions[0].get("value", ""))
    title = str(record.get("title") or cve)
    published = record.get("published") or record.get("datePublished") or record.get("cveMetadata", {}).get("datePublished")
    modified = record.get("modified") or record.get("dateUpdated") or record.get("cveMetadata", {}).get("dateUpdated")
    references = record.get("references", [])
    if not isinstance(references, list):
        references = []
    return {
        "cve": cve,
        "title": title,
        "description": record.get("description") or description,
        "affected_products": record.get("affected_products", []),
        "cvss": record.get("cvss"),
        "exploit_available": record.get("exploit_available"),
        "known_exploited": record.get("known_exploited"),
        "published": _string_or_none(published),
        "modified": _string_or_none(modified),
        "references": references,
        "source_record": record,
    }


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
