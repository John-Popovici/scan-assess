from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ngo_intel.io_utils import read_csv_dicts, write_csv
from ngo_intel.paths import ProjectPaths


class CollectorJsonError(ValueError):
    """Raised when a stored collector JSON file cannot be used."""


def load_json_document(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise CollectorJsonError(f"Could not read JSON file {source}: {exc}") from exc
    if not text.strip():
        raise CollectorJsonError(f"JSON file is empty: {source}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CollectorJsonError(f"Invalid JSON in {source}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise CollectorJsonError(f"Expected a JSON object in {source}, got {type(data).__name__}")
    return data


def import_enumeros_json(paths: ProjectPaths, path: str | Path, append: bool = True) -> dict[str, int]:
    data = load_json_document(path)
    hostname = str(data.get("hostname") or "unknown-host")
    os_info = data.get("os") if isinstance(data.get("os"), dict) else {}
    network = data.get("network_discovery") if isinstance(data.get("network_discovery"), dict) else {}

    host_rows = [
        {
            "host": hostname,
            "owner": "",
            "role": "endpoint",
            "os": _os_label(os_info),
            "source": "enumeros",
        }
    ]
    browser_rows = _enumeros_browser_rows(hostname, data.get("browsers"))
    software_rows = _enumeros_software_rows(hostname, os_info)
    service_rows, exposed_rows = _enumeros_network_rows(network)

    _write_asset_rows(paths.local_context_dir / "assets" / "hosts.csv", host_rows, ["host", "owner", "role", "os", "source"], append)
    _write_asset_rows(paths.local_context_dir / "assets" / "browsers.csv", browser_rows, ["host", "browser", "version", "source"], append)
    _write_asset_rows(paths.local_context_dir / "assets" / "software.csv", software_rows, ["host", "vendor", "product", "version", "source"], append)
    _write_asset_rows(paths.local_context_dir / "assets" / "services.csv", service_rows, ["host", "service", "port", "public_facing", "source"], append)
    _write_asset_rows(paths.local_context_dir / "assets" / "exposed_ports.csv", exposed_rows, ["host", "port", "protocol", "service", "severity", "source"], append)
    _preserve_raw(paths, "enumeros", path)
    return {
        "hosts": len(host_rows),
        "browsers": len(browser_rows),
        "software": len(software_rows),
        "services": len(service_rows),
        "exposed_ports": len(exposed_rows),
    }


def import_safesniff_json(paths: ProjectPaths, path: str | Path, append: bool = True) -> dict[str, int]:
    data = load_json_document(path)
    host_rows: list[dict[str, Any]] = []
    service_rows: list[dict[str, Any]] = []
    exposed_rows: list[dict[str, Any]] = []

    for host in data.get("hosts", []) if isinstance(data.get("hosts"), list) else []:
        ip = str(host.get("ip", ""))
        if not ip:
            continue
        host_rows.append({"host": ip, "owner": "", "role": "network-discovered", "os": "", "source": "safesniff"})
        for service in host.get("services", []) if isinstance(host.get("services"), list) else []:
            port = str(service.get("port", ""))
            name = str(service.get("service", "unknown"))
            severity = str(service.get("severity", "info"))
            service_rows.append(
                {
                    "host": ip,
                    "service": name,
                    "port": port,
                    "public_facing": "false",
                    "source": "safesniff",
                    "severity": severity,
                    "remediation": str(service.get("remediation", "")),
                    "banner": str(service.get("banner") or ""),
                }
            )
            exposed_rows.append(
                {
                    "host": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": name,
                    "severity": severity,
                    "source": "safesniff",
                }
            )

    for observed in data.get("observed_hosts", []) if isinstance(data.get("observed_hosts"), list) else []:
        ip = str(observed.get("ip", ""))
        if ip:
            host_rows.append(
                {
                    "host": ip,
                    "owner": "",
                    "role": "observed-network-host",
                    "os": str(observed.get("os_guess", "")),
                    "source": "safesniff",
                    "mac": str(observed.get("mac", "")),
                    "vendor_hint": str(observed.get("vendor_hint", "")),
                    "name_hint": str(observed.get("name_hint") or ""),
                }
            )

    _write_asset_rows(paths.local_context_dir / "assets" / "hosts.csv", host_rows, ["host", "owner", "role", "os", "source", "mac", "vendor_hint", "name_hint"], append)
    _write_asset_rows(paths.local_context_dir / "assets" / "services.csv", service_rows, ["host", "service", "port", "public_facing", "source", "severity", "remediation", "banner"], append)
    _write_asset_rows(paths.local_context_dir / "assets" / "exposed_ports.csv", exposed_rows, ["host", "port", "protocol", "service", "severity", "source"], append)
    _preserve_raw(paths, "safesniff", path)
    return {"hosts": len(host_rows), "services": len(service_rows), "exposed_ports": len(exposed_rows)}


def _enumeros_browser_rows(hostname: str, browsers: Any) -> list[dict[str, str]]:
    if not isinstance(browsers, dict):
        return []
    rows: list[dict[str, str]] = []
    for browser, version in browsers.items():
        if version not in (None, "", "null"):
            rows.append({"host": hostname, "browser": str(browser), "version": str(version), "source": "enumeros"})
    return rows


def _enumeros_software_rows(hostname: str, os_info: dict[str, Any]) -> list[dict[str, str]]:
    label = _os_label(os_info)
    if not label:
        return []
    return [
        {
            "host": hostname,
            "vendor": str(os_info.get("vendor", "")),
            "product": str(os_info.get("product_name") or os_info.get("pretty_name") or os_info.get("platform") or "Operating System"),
            "version": str(os_info.get("product_version") or os_info.get("display_version") or os_info.get("version_id") or os_info.get("build") or ""),
            "source": "enumeros",
        }
    ]


def _enumeros_network_rows(network: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    service_rows: list[dict[str, str]] = []
    exposed_rows: list[dict[str, str]] = []
    hosts = network.get("hosts", [])
    if not isinstance(hosts, list):
        return service_rows, exposed_rows
    for host in hosts:
        ip = str(host.get("ip", ""))
        for port_item in host.get("open_ports", []) if isinstance(host.get("open_ports"), list) else []:
            port = str(port_item.get("port", port_item)) if isinstance(port_item, dict) else str(port_item)
            service = _service_name(port)
            service_rows.append({"host": ip, "service": service, "port": port, "public_facing": "false", "source": "enumeros"})
            exposed_rows.append({"host": ip, "port": port, "protocol": "tcp", "service": service, "severity": "", "source": "enumeros"})
    return service_rows, exposed_rows


def _os_label(os_info: dict[str, Any]) -> str:
    parts = [
        os_info.get("product_name") or os_info.get("pretty_name") or os_info.get("platform"),
        os_info.get("product_version") or os_info.get("display_version") or os_info.get("version_id") or os_info.get("build"),
    ]
    return " ".join(str(part) for part in parts if part not in (None, ""))


def _service_name(port: str) -> str:
    return {
        "22": "ssh",
        "53": "dns",
        "80": "http",
        "443": "https",
        "445": "smb",
        "3389": "rdp",
    }.get(port, "unknown")


def _write_asset_rows(path: Path, rows: list[dict[str, Any]], headers: list[str], append: bool) -> None:
    if not rows:
        if not path.exists():
            write_csv(path, [], headers=headers)
        return
    existing = read_csv_dicts(path) if append and path.exists() else []
    write_csv(path, _dedupe_rows([*existing, *rows], headers), headers=headers)


def _dedupe_rows(rows: list[dict[str, Any]], headers: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(str(row.get(header, "")) for header in headers)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _preserve_raw(paths: ProjectPaths, source: str, path: str | Path) -> None:
    src = Path(path)
    out_dir = paths.local_context_dir / "imported" / source
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
