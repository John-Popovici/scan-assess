from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .io_utils import read_csv_dicts, read_jsonl
from .paths import ProjectPaths


HIGH_RISK_PORTS = {"23", "135", "139", "445", "3389", "5900", "5985", "5986"}


def build_overview(paths: ProjectPaths) -> dict[str, Any]:
    """Build a compact operator/AI overview across local context and reports."""
    assets = paths.local_context_dir / "assets"
    mini_dir = paths.data_dir / "mini" / "current"
    hosts = read_csv_dicts(assets / "hosts.csv")
    software = read_csv_dicts(assets / "software.csv")
    browsers = read_csv_dicts(assets / "browsers.csv")
    services = read_csv_dicts(assets / "services.csv")
    exposed_ports = read_csv_dicts(assets / "exposed_ports.csv")
    dns_matches = read_jsonl(mini_dir / "dnscap_highlights.jsonl")
    enumeros_findings = read_jsonl(mini_dir / "enumeros_findings.jsonl")
    all_threat_items = read_jsonl(mini_dir / "threat_items.jsonl")
    all_vulnerabilities = read_jsonl(paths.normalized_date_dir() / "vulnerabilities.jsonl")
    threat_items = [item for item in all_threat_items if not _is_demo_path(str(item.get("evidence_path") or ""))]
    vulnerabilities = [item for item in all_vulnerabilities if not _is_demo_path(str(item.get("raw_path") or ""))]
    brief = _read_first_json(mini_dir / "ngo_relevance_brief.json")
    deep = _read_first_json(mini_dir / "deep_evidence.json")
    update_status = _update_status(enumeros_findings)
    devices = _devices(hosts, software, browsers, services, exposed_ports, dns_matches, update_status)
    service_exposure = _service_exposure(exposed_ports, services)
    observed_products = _observed_products(software, browsers, hosts)
    vulnerability_context = _vulnerability_context(vulnerabilities, observed_products)
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "project_root": str(paths.project_root),
        "summary": {
            "devices": len(devices),
            "browser_records": len(browsers),
            "software_records": len(software),
            "service_records": len(services),
            "safesniff_services": sum(1 for row in services if row.get("source") == "safesniff"),
            "safesniff_high_exposures": sum(1 for row in exposed_ports if row.get("source") == "safesniff" and row.get("severity") == "high"),
            "local_dns_threat_matches": len(dns_matches),
            "outdated_assets": len([item for item in update_status if item.get("status") == "outdated"]),
            "unknown_update_status": len([item for item in update_status if item.get("status") == "unknown"]),
            "brief_items": brief.get("boundaries", {}).get("brief_items_retained", 0),
            "deep_evidence_records": deep.get("record_count", 0),
            "threat_context_items": len(threat_items),
            "matched_vulnerabilities": sum(1 for item in vulnerability_context if item["match_status"] == "matched_local_inventory"),
            "demo_threat_items_hidden": len(all_threat_items) - len(threat_items),
            "demo_vulnerabilities_hidden": len(all_vulnerabilities) - len(vulnerabilities),
        },
        "devices": devices,
        "service_exposure": service_exposure,
        "update_status": update_status,
        "threat_context": _threat_context(threat_items),
        "vulnerability_context": vulnerability_context,
        "local_dns_threat_matches": dns_matches,
        "correlation_hints": _correlation_hints(devices, service_exposure, dns_matches, update_status),
        "outputs": {
            "brief_json": str(mini_dir / "ngo_relevance_brief.json"),
            "deep_evidence_json": str(mini_dir / "deep_evidence.json"),
            "human_brief": str(mini_dir / "ngo_relevance_brief.md"),
        },
    }


def _devices(
    hosts: list[dict[str, str]],
    software: list[dict[str, str]],
    browsers: list[dict[str, str]],
    services: list[dict[str, str]],
    exposed_ports: list[dict[str, str]],
    dns_matches: list[dict[str, Any]],
    update_status: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_host: dict[str, dict[str, Any]] = {}
    for host in hosts:
        key = host.get("host") or host.get("name_hint") or "unknown"
        by_host.setdefault(key, _empty_device(key))
        by_host[key]["roles"].add(host.get("role", ""))
        by_host[key]["os"].add(host.get("os", ""))
        by_host[key]["sources"].add(host.get("source", "manual") or "manual")
    for row in software:
        key = row.get("host") or "unknown"
        by_host.setdefault(key, _empty_device(key))["software"].append(row)
    for row in browsers:
        key = row.get("host") or "unknown"
        by_host.setdefault(key, _empty_device(key))["browsers"].append(row)
    service_lookup = defaultdict(list)
    for row in exposed_ports:
        service_lookup[row.get("host") or "unknown"].append(row)
    for row in services:
        key = row.get("host") or "unknown"
        service_row = dict(row)
        matching_ports = [
            port
            for port in service_lookup[key]
            if port.get("port") == row.get("port") and (not row.get("source") or port.get("source") == row.get("source"))
        ]
        if matching_ports and not service_row.get("severity"):
            service_row["severity"] = matching_ports[0].get("severity", "")
        by_host.setdefault(key, _empty_device(key))["services"].append(service_row)
    for row in dns_matches:
        key = str(row.get("host") or "unknown")
        by_host.setdefault(key, _empty_device(key))["threat_dns_matches"].append(row)
    for row in update_status:
        key = str(row.get("host") or "unknown")
        by_host.setdefault(key, _empty_device(key))["update_status"].append(row)
    devices: list[dict[str, Any]] = []
    for item in by_host.values():
        devices.append(
            {
                "host": item["host"],
                "roles": sorted(value for value in item.get("roles", set()) if value),
                "os": sorted(value for value in item.get("os", set()) if value),
                "sources": sorted(value for value in item.get("sources", set()) if value),
                "software_count": len(item["software"]),
                "browser_count": len(item["browsers"]),
                "services": item["services"],
                "high_risk_services": _dedupe_services([svc for svc in item["services"] if _is_high_risk_service(svc)]),
                "threat_dns_matches": item["threat_dns_matches"],
                "update_status": item["update_status"],
                "outdated_count": len([row for row in item["update_status"] if row.get("status") == "outdated"]),
                "unknown_update_count": len([row for row in item["update_status"] if row.get("status") == "unknown"]),
            }
        )
    return sorted(devices, key=lambda row: (row["outdated_count"], len(row["high_risk_services"]), len(row["threat_dns_matches"]), row["host"]), reverse=True)


def _empty_device(host: str) -> dict[str, Any]:
    return {"host": host, "roles": set(), "os": set(), "sources": set(), "software": [], "browsers": [], "services": [], "threat_dns_matches": [], "update_status": []}


def _service_exposure(exposed_ports: list[dict[str, str]], services: list[dict[str, str]]) -> list[dict[str, Any]]:
    service_details = {(row.get("host"), row.get("port"), row.get("source")): row for row in services}
    rows: list[dict[str, Any]] = []
    for row in exposed_ports:
        detail = service_details.get((row.get("host"), row.get("port"), row.get("source")), {})
        merged = {**detail, **row}
        merged["high_risk"] = _is_high_risk_service(merged)
        merged["correlation_use"] = _service_correlation_use(merged)
        rows.append(merged)
    return sorted(rows, key=lambda row: (row.get("severity") == "high", row.get("high_risk"), row.get("host", "")), reverse=True)


def _dedupe_services(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    output: list[dict[str, Any]] = []
    for service in services:
        key = (str(service.get("service", "")), str(service.get("port", "")))
        if key in seen:
            continue
        seen.add(key)
        output.append(service)
    return output


def _is_high_risk_service(row: dict[str, Any]) -> bool:
    return str(row.get("severity", "")).lower() == "high" or str(row.get("port", "")) in HIGH_RISK_PORTS


def _service_correlation_use(row: dict[str, Any]) -> str:
    port = str(row.get("port", ""))
    service = str(row.get("service", "")).lower()
    if port == "445" or service == "smb":
        return "Correlate with Windows/SMB vulnerabilities and lateral-movement risk."
    if port == "3389" or service == "rdp":
        return "Correlate with remote-access exposure and credential-theft risk."
    if port in {"80", "443", "8080", "8443"} or service in {"http", "https"}:
        return "Correlate with web-stack vulnerabilities and public-service exposure."
    if port in {"5985", "5986"}:
        return "Correlate with Windows remote-management exposure."
    return "Use as local service exposure context."


def _correlation_hints(
    devices: list[dict[str, Any]],
    service_exposure: list[dict[str, Any]],
    dns_matches: list[dict[str, Any]],
    update_status: list[dict[str, Any]],
) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    outdated = [item for item in update_status if item.get("status") == "outdated"]
    if outdated:
        hosts = sorted({str(item.get("host") or "unknown") for item in outdated})
        hints.append(
            {
                "kind": "outdated_software",
                "summary": f"{len(outdated)} Enumeros outdated OS/browser/software finding(s) across {len(hosts)} host(s): {', '.join(hosts[:4])}.",
            }
        )
    if dns_matches:
        hints.append({"kind": "dns_threat_match", "summary": f"{len(dns_matches)} local DNS threat match(es) should be reviewed before treating URLhaus/MISP URL data as relevant."})
    high_services = [item for item in service_exposure if item.get("high_risk")]
    if high_services:
        hints.append({"kind": "safesniff_service_exposure", "summary": f"{len(high_services)} high-risk or high-severity service exposure(s) should influence vulnerability relevance."})
    combined = [device for device in devices if device.get("high_risk_services") and device.get("threat_dns_matches")]
    for device in combined:
        hints.append({"kind": "combined_dns_and_service", "summary": f"{device['host']} has both suspicious DNS activity and high-risk exposed services."})
    if not hints:
        hints.append({"kind": "no_local_correlation", "summary": "No local DNS threat matches or high-risk service exposures were found in current context."})
    return hints


def _update_status(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("kind") not in {"outdated_software", "unknown_version_status"}:
            continue
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        status = str(evidence.get("status") or "").lower()
        if finding.get("kind") == "outdated_software":
            status = "outdated"
        elif not status or status == "not_installed_or_not_detected":
            status = "unknown"
        rows.append(
            {
                "host": finding.get("host") or "unknown",
                "subject": finding.get("subject") or evidence.get("name") or "unknown",
                "status": status,
                "installed": evidence.get("installed"),
                "latest": evidence.get("latest"),
                "source": "enumeros",
                "source_detail": evidence.get("source", ""),
                "severity_hint": finding.get("severity_hint", "review"),
                "title": finding.get("title"),
                "evidence_path": finding.get("evidence_path"),
                "suggested_ai_use": finding.get("suggested_ai_use"),
            }
        )
    status_rank = {"outdated": 2, "unknown": 1}
    return sorted(rows, key=lambda row: (status_rank.get(str(row.get("status")), 0), str(row.get("host")), str(row.get("subject"))), reverse=True)


def _threat_context(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        source = str(item.get("source") or "unknown")
        threat_types = item.get("threat_type") if isinstance(item.get("threat_type"), list) else []
        theme_labels = [theme.get("label") for theme in item.get("theme_matches", []) if isinstance(theme, dict)]
        label = str(theme_labels[0] if theme_labels else (threat_types[0] if threat_types else item.get("kind") or "context"))
        scope = "broad context only" if any(theme.get("broad_context_only") for theme in item.get("theme_matches", []) if isinstance(theme, dict)) else str(item.get("relevance_level") or "context")
        key = (source, label, scope)
        grouped.setdefault(
            key,
            {
                "source": source,
                "theme_or_type": label,
                "scope": scope,
                "count": 0,
                "examples": [],
            },
        )
        grouped[key]["count"] += 1
        if len(grouped[key]["examples"]) < 3:
            grouped[key]["examples"].append(
                {
                    "title": item.get("title"),
                    "value": item.get("value") or item.get("vuln_id"),
                    "domain": item.get("domain", ""),
                    "evidence_path": item.get("evidence_path"),
                }
            )
    return sorted(grouped.values(), key=lambda row: (row["count"], row["source"]), reverse=True)


def _observed_products(software: list[dict[str, str]], browsers: list[dict[str, str]], hosts: list[dict[str, str]]) -> list[dict[str, str]]:
    observed: list[dict[str, str]] = []
    for row in software:
        observed.append({"host": row.get("host", ""), "product": row.get("product", ""), "version": row.get("version", ""), "kind": "software"})
    for row in browsers:
        observed.append({"host": row.get("host", ""), "product": row.get("browser", ""), "version": row.get("version", ""), "kind": "browser"})
    for row in hosts:
        observed.append({"host": row.get("host", ""), "product": row.get("os", ""), "version": "", "kind": "os"})
    return [item for item in observed if item["product"]]


def _vulnerability_context(vulnerabilities: list[dict[str, Any]], observed_products: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        if not vuln.get("vuln_id") or vuln.get("vuln_id") == "UNKNOWN":
            continue
        matches = _match_vulnerability_products(vuln, observed_products)
        if not matches and not _mentions_interesting_product(vuln):
            continue
        rows.append(
            {
                "vuln_id": vuln.get("vuln_id"),
                "title": vuln.get("title") or vuln.get("vuln_id"),
                "source": vuln.get("source"),
                "match_status": "matched_local_inventory" if matches else "watch_needs_inventory_confirmation",
                "matched_products": matches,
                "cvss": vuln.get("cvss"),
                "exploit_available": vuln.get("exploit_available"),
                "known_exploited": vuln.get("known_exploited"),
                "raw_path": vuln.get("raw_path"),
                "is_demo": _is_demo_path(str(vuln.get("raw_path") or "")),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["match_status"] == "matched_local_inventory",
            bool(row.get("known_exploited")),
            bool(row.get("exploit_available")),
            float(row.get("cvss") or 0),
        ),
        reverse=True,
    )


def _match_vulnerability_products(vuln: dict[str, Any], observed_products: list[dict[str, str]]) -> list[dict[str, str]]:
    affected = vuln.get("affected_products") if isinstance(vuln.get("affected_products"), list) else []
    text = " ".join([str(vuln.get("title") or ""), str(vuln.get("description") or ""), json.dumps(affected)]).lower()
    affected_keys = {_product_key(item.get("product")) for item in affected if isinstance(item, dict)}
    matches: list[dict[str, str]] = []
    for item in observed_products:
        key = _product_key(item.get("product"))
        if key and (key in affected_keys or key in text):
            matches.append(item)
    return matches


def _mentions_interesting_product(vuln: dict[str, Any]) -> bool:
    products = {"chrome", "edge", "firefox", "safari", "windows", "macos", "office", "acrobat", "openssl", "wordpress"}
    text = " ".join([str(vuln.get("title") or ""), str(vuln.get("description") or ""), json.dumps(vuln.get("affected_products", []))]).lower()
    return any(product in text for product in products)


def _product_key(value: Any) -> str:
    text = str(value or "").lower().strip()
    aliases = {
        "google chrome": "chrome",
        "microsoft edge": "edge",
        "mozilla firefox": "firefox",
        "microsoft windows": "windows",
        "windows 11": "windows",
        "mac os": "macos",
        "microsoft office": "office",
        "adobe acrobat reader": "acrobat",
    }
    text = aliases.get(text, text)
    return " ".join(text.replace("-", " ").replace("_", " ").split())


def _is_demo_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in ["sample", "demo_", "tests/fixtures"])


def _read_first_json(path) -> dict[str, Any]:
    import json

    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if text.strip() else {}
