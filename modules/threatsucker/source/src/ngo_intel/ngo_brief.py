from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .io_utils import read_jsonl, stable_hash, write_csv, write_jsonl
from .paths import ProjectPaths


def build_ngo_relevance_brief(paths: ProjectPaths) -> dict[str, int]:
    mini_dir = paths.data_dir / "mini" / "current"
    items = read_jsonl(mini_dir / "threat_items.jsonl")
    live_items = [item for item in items if not _is_demo_evidence(item)]
    local_url_items = [_brief_item(item) for item in _locally_observed_url_items(live_items, mini_dir)]
    vulnerability_items = _software_vulnerability_items(paths)
    relevant = sorted([*local_url_items, *vulnerability_items], key=_sort_key, reverse=True)
    deep_evidence = _deep_evidence_json(paths, live_items, relevant)

    out_md = mini_dir / "ngo_relevance_brief.md"
    (mini_dir / "deep_evidence.json").write_text(json.dumps(deep_evidence, indent=2), encoding="utf-8")
    write_jsonl(mini_dir / "ngo_relevance_items.jsonl", relevant)
    write_csv(mini_dir / "ngo_relevance_items.csv", relevant)
    brief_json = _brief_json(paths, relevant, live_items, len(items) - len(live_items), "deep_evidence.json")
    out_md.write_text(_render_brief(brief_json), encoding="utf-8")
    (mini_dir / "ngo_relevance_brief.json").write_text(json.dumps(brief_json, indent=2), encoding="utf-8")
    return {"brief_items": len(relevant), "source_items": len(live_items)}


def _locally_observed_url_items(items: list[dict[str, Any]], mini_dir: Path) -> list[dict[str, Any]]:
    dns_matches = read_jsonl(mini_dir / "dnscap_highlights.jsonl") if (mini_dir / "dnscap_highlights.jsonl").exists() else []
    matched_domains = {str(match.get("domain") or match.get("queried_domain") or "").lower() for match in dns_matches}
    matched_domains.discard("")
    if not matched_domains:
        return []
    local_items: list[dict[str, Any]] = []
    for item in items:
        domain = str(item.get("domain") or "").lower()
        if domain and domain in matched_domains:
            copied = dict(item)
            copied["relevance_level"] = "local_dns_observed"
            copied["local_evidence"] = [match for match in dns_matches if str(match.get("domain") or match.get("queried_domain") or "").lower() == domain]
            local_items.append(copied)
    return local_items


def _software_vulnerability_items(paths: ProjectPaths) -> list[dict[str, Any]]:
    observed = _load_observed_software(paths)
    vulnerabilities = read_jsonl(paths.normalized_date_dir() / "vulnerabilities.jsonl")
    items: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        if _is_demo_evidence({"evidence_path": vuln.get("raw_path")}):
            continue
        matches = _matched_observed_products(vuln, observed)
        if matches:
            items.append(_vulnerability_brief_item(vuln, matches, "observed_software_match"))
        elif _mentions_standard_software(vuln) and _high_impact_vulnerability(vuln):
            items.append(_vulnerability_brief_item(vuln, [], "standard_software_watch"))
    return items


def _is_demo_evidence(item: dict[str, Any]) -> bool:
    evidence = str(item.get("evidence_path") or "").lower()
    demo_markers = [
        "demo_",
        "_sample.",
        "sample.json",
        "sample.jsonl",
        "tests/fixtures",
    ]
    return any(marker in evidence for marker in demo_markers)


def _brief_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "item_id": item.get("item_id"),
        "title": item.get("title"),
        "kind": item.get("kind"),
        "source": item.get("source"),
        "value": item.get("value") or item.get("vuln_id"),
        "domain": item.get("domain", ""),
        "relevance_level": item.get("relevance_level", "context"),
        "theme_matches": item.get("theme_matches", []),
        "local_evidence": item.get("local_evidence", []),
        "filtering_rules_used": _filtering_rules(item),
        "deep_evidence_ids": [_threat_evidence_id(item), *[_local_dns_evidence_id(entry) for entry in item.get("local_evidence", [])]],
        "why_relevant_to_luxembourg_ngos": _why_relevant(item),
        "evidence_path": item.get("evidence_path"),
        "suggested_ai_use": item.get("suggested_ai_use"),
    }


def _vulnerability_brief_item(vuln: dict[str, Any], matches: list[dict[str, Any]], rule_id: str) -> dict[str, Any]:
    high_impact_reasons = _vulnerability_impact_reasons(vuln)
    title = vuln.get("title") or vuln.get("vuln_id")
    if rule_id == "observed_software_match":
        relevance = [
            "Vulnerability affected product matches observed browser, OS, or installed software inventory.",
            *high_impact_reasons,
        ]
        suggested = "Use this as software exposure context; verify installed versions before recommending patch action."
    else:
        relevance = [
            "Vulnerability appears to concern common endpoint/server software, but no local product match was found yet.",
            *high_impact_reasons,
        ]
        suggested = "Use this only as an inventory-confirmation prompt, not as a local exposure finding."
    return {
        "item_id": vuln.get("vuln_id"),
        "title": title,
        "kind": "vulnerability",
        "source": vuln.get("source"),
        "value": vuln.get("vuln_id"),
        "domain": "",
        "relevance_level": rule_id,
        "theme_matches": [],
        "local_evidence": matches,
        "filtering_rules_used": [
            {
                "id": rule_id,
                "label": "Observed software vulnerability match" if matches else "Standard software vulnerability watch",
                "matched_terms": sorted({match.get("observed_product", "") for match in matches if match.get("observed_product")}),
                "scope": "local inventory match" if matches else "needs inventory confirmation",
            }
        ],
        "deep_evidence_ids": [_vulnerability_evidence_id(vuln), *[_inventory_evidence_id(match) for match in matches]],
        "why_relevant_to_luxembourg_ngos": relevance,
        "evidence_path": vuln.get("raw_path"),
        "suggested_ai_use": suggested,
        "cvss": vuln.get("cvss"),
        "exploit_available": vuln.get("exploit_available"),
        "known_exploited": vuln.get("known_exploited"),
        "affected_products": vuln.get("affected_products", []),
    }


def _why_relevant(item: dict[str, Any]) -> list[str]:
    reasons = item.get("include_reasons", [])
    output: list[str] = []
    for reason in reasons:
        if reason.startswith("brand_term"):
            output.append("Mentions or imitates a brand/payment/document service commonly used by small NGOs.")
        elif reason.startswith("sector_term"):
            output.append("Matches NGO-relevant themes such as donations, invoices, payments, or charity operations.")
        elif reason.startswith("country_term"):
            output.append("Matches Luxembourg/LU profile terms.")
        elif reason.startswith("impact_signal"):
            output.append("Vulnerability has a high-impact signal such as exploit availability, known exploitation, or high CVSS.")
        elif reason.startswith("threat_focus: phishing") or reason.startswith("threat_focus: credential"):
            output.append("Credential theft/phishing is high-impact for low-capacity organizations.")
        elif reason.startswith("threat_focus: malware"):
            output.append("Matched local DNS evidence; URL/domain indicators are otherwise excluded from this brief.")
    if not output:
        output.append("Included as general threat context, not as evidence of local targeting.")
    return list(dict.fromkeys(output))


def _brief_json(
    paths: ProjectPaths,
    relevant: list[dict[str, Any]],
    source_items: list[dict[str, Any]],
    demo_excluded: int,
    deep_evidence_path: str,
) -> dict[str, Any]:
    generated = datetime.now(timezone.utc).isoformat()
    observed_software = _load_observed_software(paths)
    direct = [item for item in relevant if item["relevance_level"] == "profile_matched"]
    local_urls = [item for item in relevant if item["relevance_level"] == "local_dns_observed"]
    matched_vuln = [item for item in relevant if item["relevance_level"] == "observed_software_match"]
    watch_vuln = [item for item in relevant if item["relevance_level"] == "standard_software_watch"]
    theme_counts = _theme_counts(relevant)
    return {
        "title": "Luxembourg NGO Relevance Brief",
        "generated": generated,
        "mode": "mini/basic",
        "scoring_applied": False,
        "deep_evidence_path": deep_evidence_path,
        "what_this_is": "A compact brief of recently collected public threat information that may be useful for an AI reasoning about Luxembourgish NGOs. URL/domain indicators are included only when local DNS evidence observed them. Vulnerabilities are included when they match observed browsers, OS, or installed software, or when they concern common software and require inventory confirmation.",
        "most_relevant_themes": _theme_count_objects(theme_counts),
        "sections": {
            "observed_browser_os_software_context": observed_software,
            "profile_matched_items": direct[:15],
            "locally_observed_url_indicators": local_urls[:15],
            "matched_browser_os_software_vulnerabilities": matched_vuln[:15],
            "standard_software_vulnerabilities_needing_inventory_confirmation": watch_vuln[:10],
        },
        "boundaries": {
            "source_items_considered": len(source_items),
            "demo_sample_items_excluded": demo_excluded,
            "brief_items_retained": len(relevant),
            "notes": [
                "These items are context for an AI, not a blocklist and not attribution.",
                "Filtering rules explain why an item was retained; they do not prove local targeting.",
                "Seen-in-the-wild URL/domain indicators are intentionally excluded unless DNScap or equivalent local DNS evidence matched them.",
                "Vulnerability entries should be verified against Enumeros/SafeSniff/asset inventory before action.",
                f"Deep evidence is stored in {deep_evidence_path}; report items reference stable evidence IDs.",
            ],
        },
    }


def _render_brief(brief: dict[str, Any]) -> str:
    sections = brief["sections"]
    boundaries = brief["boundaries"]
    lines = [
        f"# {brief['title']}",
        "",
        f"Generated: {brief['generated']}",
        "Mode: mini/basic, no scoring",
        f"Deep evidence: {brief['deep_evidence_path']}",
        "",
        "## What This Is",
        "",
        brief["what_this_is"],
        "",
        "## Most Relevant Themes",
        "",
        *_render_theme_counts(brief["most_relevant_themes"]),
        "",
        "## Observed Browser, OS, and Software Context",
        "",
    ]
    lines.extend(_render_observed_software(sections["observed_browser_os_software_context"]))
    lines.extend(
        [
            "",
        "## Profile-Matched Phishing/Brand Items",
        "",
        ]
    )
    lines.extend(_render_items(sections["profile_matched_items"]))
    lines.extend(["", "## Locally Observed URL/Domain Indicators", ""])
    lines.extend(_render_items(sections["locally_observed_url_indicators"]))
    lines.extend(["", "## Matched Browser, OS, and Software Vulnerabilities", ""])
    lines.extend(_render_items(sections["matched_browser_os_software_vulnerabilities"]))
    lines.extend(["", "## Standard Software Vulnerabilities Needing Inventory Confirmation", ""])
    lines.extend(_render_items(sections["standard_software_vulnerabilities_needing_inventory_confirmation"]))
    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            f"- Source items considered: {boundaries['source_items_considered']}",
            f"- Demo/sample items excluded from this live brief: {boundaries['demo_sample_items_excluded']}",
            f"- Brief items retained: {boundaries['brief_items_retained']}",
            *[f"- {note}" for note in boundaries["notes"]],
        ]
    )
    return "\n".join(lines) + "\n"


def _render_observed_software(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["- No local browser, OS, or software inventory was available."]
    lines: list[str] = []
    for item in items[:25]:
        host = item.get("host") or "unknown host"
        product = item.get("observed_product") or "unknown product"
        version = f" {item['observed_version']}" if item.get("observed_version") else ""
        source_type = item.get("source_type") or "inventory"
        evidence_id = item.get("deep_evidence_id", "no evidence id")
        lines.append(f"- {host}: {product}{version} ({source_type}; evidence: {evidence_id})")
    return lines


def _render_items(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["- None retained."]
    lines: list[str] = []
    for item in items:
        lines.extend(
            [
                f"### {item['title']}",
                "",
                f"- Source: {item['source']}",
                f"- Value: {item['value']}",
                f"- Filtering rules used: {_theme_rule_summary(item)}",
                f"- Relevance: {'; '.join(item['why_relevant_to_luxembourg_ngos'])}",
                f"- Local evidence: {_local_evidence_summary(item)}",
                f"- Deep evidence IDs: {', '.join(item.get('deep_evidence_ids', [])) or 'none'}",
                f"- Evidence: {item.get('evidence_path') or 'unknown'}",
                "",
            ]
        )
    return lines


def _theme_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        for theme in item.get("theme_matches", []):
            label = str(theme.get("label") or theme.get("id") or "Unknown theme")
            counts[label] = counts.get(label, 0) + 1
    return counts


def _theme_count_objects(theme_counts: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {"theme": label, "retained_items": count}
        for label, count in sorted(theme_counts.items(), key=lambda row: row[1], reverse=True)
    ]


def _render_theme_counts(theme_counts: list[dict[str, Any]]) -> list[str]:
    if not theme_counts:
        return [
            "- No direct profile themes were matched in the retained live data.",
            "- Broad malware delivery items may still be useful as a watch list if local DNS or endpoint telemetry later matches them.",
        ]
    return [f"- {item['theme']}: {item['retained_items']} retained item(s)" for item in theme_counts]


def _theme_rule_summary(item: dict[str, Any]) -> str:
    if item.get("filtering_rules_used"):
        return "; ".join(_structured_rule_summary(rule) for rule in item["filtering_rules_used"])
    summaries: list[str] = []
    for theme in item.get("theme_matches", []):
        rule_id = str(theme.get("id") or "unnamed_theme")
        label = str(theme.get("label") or rule_id)
        terms = ", ".join(str(term) for term in theme.get("matched_terms", [])) or "no terms recorded"
        scope = "broad context only" if theme.get("broad_context_only") else "profile relevance"
        summaries.append(f"{rule_id} ({label}; matched: {terms}; scope: {scope})")
    return "; ".join(summaries) if summaries else "none"


def _structured_rule_summary(rule: dict[str, Any]) -> str:
    rule_id = str(rule.get("id") or "unnamed_rule")
    label = str(rule.get("label") or rule_id)
    terms = ", ".join(str(term) for term in rule.get("matched_terms", [])) or "no terms recorded"
    scope = str(rule.get("scope") or "profile relevance")
    return f"{rule_id} ({label}; matched: {terms}; scope: {scope})"


def _filtering_rules(item: dict[str, Any]) -> list[dict[str, Any]]:
    if item.get("relevance_level") == "local_dns_observed":
        return [
            {
                "id": "local_dns_observed_indicator",
                "label": "URL/domain indicator observed in local DNS evidence",
                "matched_terms": [item.get("domain") or item.get("value")],
                "scope": "local DNS match",
            }
        ]
    rules: list[dict[str, Any]] = []
    for theme in item.get("theme_matches", []):
        rules.append(
            {
                "id": theme.get("id"),
                "label": theme.get("label"),
                "matched_terms": theme.get("matched_terms", []),
                "scope": "broad context only" if theme.get("broad_context_only") else "profile relevance",
            }
        )
    return rules


def _local_evidence_summary(item: dict[str, Any]) -> str:
    evidence = item.get("local_evidence") or []
    if not evidence:
        return "none"
    bits: list[str] = []
    for entry in evidence[:3]:
        if entry.get("host") and (entry.get("domain") or entry.get("queried_domain")):
            bits.append(f"{entry.get('host')} queried {entry.get('domain') or entry.get('queried_domain')}")
        elif entry.get("host") and entry.get("observed_product"):
            bits.append(f"{entry.get('host')} has {entry.get('observed_product')} {entry.get('observed_version') or ''}".strip())
        elif entry.get("observed_product"):
            bits.append(f"{entry.get('observed_product')} {entry.get('observed_version') or ''}".strip())
    return "; ".join(bits) if bits else f"{len(evidence)} local evidence item(s)"


def _load_observed_software(paths: ProjectPaths) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    assets = paths.local_context_dir / "assets"
    for row in _read_csv(assets / "software.csv"):
        observed.append(_observed(row.get("host"), row.get("product"), row.get("version"), "software"))
    for row in _read_csv(assets / "browsers.csv"):
        observed.append(_observed(row.get("host"), row.get("browser"), row.get("version"), "browser"))
    for row in _read_csv(assets / "hosts.csv"):
        observed.append(_observed(row.get("host") or row.get("name_hint"), row.get("os"), "", "os"))
    return [item for item in observed if item["observed_product"]]


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _observed(host: Any, product: Any, version: Any, source_type: str) -> dict[str, Any]:
    product_value = str(product or "").strip()
    item = {
        "host": str(host or "").strip(),
        "observed_product": product_value,
        "observed_product_key": _product_key(product_value),
        "observed_version": str(version or "").strip(),
        "source_type": source_type,
    }
    item["deep_evidence_id"] = _inventory_evidence_id(item)
    return item


def _matched_observed_products(vuln: dict[str, Any], observed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    affected = vuln.get("affected_products") if isinstance(vuln.get("affected_products"), list) else []
    vuln_text = " ".join([str(vuln.get("title") or ""), str(vuln.get("description") or ""), json.dumps(affected)]).lower()
    matches: list[dict[str, Any]] = []
    affected_keys = {_product_key(item.get("product")) for item in affected if isinstance(item, dict)}
    for item in observed:
        key = item["observed_product_key"]
        if not key:
            continue
        if key in affected_keys or key in vuln_text:
            matches.append({k: v for k, v in item.items() if k != "observed_product_key"})
    return matches


def _product_key(value: Any) -> str:
    text = str(value or "").lower()
    replacements = {
        "google chrome": "chrome",
        "microsoft edge": "edge",
        "mozilla firefox": "firefox",
        "mac os": "macos",
        "microsoft windows": "windows",
        "microsoft office": "office",
        "adobe acrobat reader": "acrobat",
    }
    text = replacements.get(text, text)
    for suffix in [" browser", " reader"]:
        text = text.replace(suffix, "")
    return " ".join(text.replace("-", " ").replace("_", " ").split())


def _mentions_standard_software(vuln: dict[str, Any]) -> bool:
    terms = {
        "windows",
        "macos",
        "chrome",
        "edge",
        "firefox",
        "safari",
        "office",
        "outlook",
        "word",
        "excel",
        "acrobat",
        "openssl",
        "libexpat",
        "curl",
    }
    affected = vuln.get("affected_products") if isinstance(vuln.get("affected_products"), list) else []
    text = " ".join([str(vuln.get("title") or ""), str(vuln.get("description") or ""), json.dumps(affected)]).lower()
    return any(term in text for term in terms)


def _high_impact_vulnerability(vuln: dict[str, Any]) -> bool:
    cvss = vuln.get("cvss")
    return bool(vuln.get("known_exploited") or vuln.get("exploit_available") or (isinstance(cvss, int | float) and cvss >= 8))


def _vulnerability_impact_reasons(vuln: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if vuln.get("known_exploited"):
        reasons.append("Known exploitation signal is present.")
    if vuln.get("exploit_available"):
        reasons.append("Exploit availability signal is present.")
    cvss = vuln.get("cvss")
    if isinstance(cvss, int | float) and cvss >= 8:
        reasons.append(f"High CVSS signal is present: {cvss}.")
    return reasons


def _deep_evidence_json(paths: ProjectPaths, live_items: list[dict[str, Any]], report_items: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the drill-down evidence store referenced by compact reports."""
    mini_dir = paths.data_dir / "mini" / "current"
    dns_matches = read_jsonl(mini_dir / "dnscap_highlights.jsonl")
    vulnerabilities = [
        vuln
        for vuln in read_jsonl(paths.normalized_date_dir() / "vulnerabilities.jsonl")
        if not _is_demo_evidence({"evidence_path": vuln.get("raw_path")})
    ]
    observed_software = _load_observed_software(paths)
    records: list[dict[str, Any]] = []
    records.extend(_threat_evidence_record(item) for item in live_items)
    records.extend(_vulnerability_evidence_record(vuln) for vuln in vulnerabilities)
    records.extend(_inventory_evidence_record(item) for item in observed_software)
    records.extend(_local_dns_evidence_record(item) for item in dns_matches)
    report_references = {evidence_id for item in report_items for evidence_id in item.get("deep_evidence_ids", [])}
    report_references.update(item["deep_evidence_id"] for item in observed_software if item.get("deep_evidence_id"))
    return {
        "title": "ThreatSucker Deep Evidence",
        "generated": datetime.now(timezone.utc).isoformat(),
        "purpose": "Structured drill-down evidence for AI reasoning. Compact reports should reference evidence_id values instead of copying every field.",
        "schema_version": 1,
        "record_count": len(records),
        "report_references": sorted(report_references),
        "records": records,
    }


def _threat_evidence_record(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": _threat_evidence_id(item),
        "record_type": "threat_item",
        "kind": item.get("kind"),
        "source": item.get("source"),
        "title": item.get("title"),
        "value": item.get("value"),
        "domain": item.get("domain"),
        "indicator_type": item.get("indicator_type"),
        "threat_type": item.get("threat_type", []),
        "theme_matches": item.get("theme_matches", []),
        "include_reasons": item.get("include_reasons", []),
        "relevance_level": item.get("relevance_level"),
        "raw_evidence_path": item.get("evidence_path"),
        "suggested_ai_use": item.get("suggested_ai_use"),
    }


def _vulnerability_evidence_record(vuln: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": _vulnerability_evidence_id(vuln),
        "record_type": "vulnerability",
        "source": vuln.get("source"),
        "vuln_id": vuln.get("vuln_id"),
        "title": vuln.get("title"),
        "description": vuln.get("description"),
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
        "affected_products": vuln.get("affected_products", []),
        "cvss": vuln.get("cvss"),
        "exploit_available": vuln.get("exploit_available"),
        "known_exploited": vuln.get("known_exploited"),
        "references": vuln.get("references", []),
        "raw_evidence_path": vuln.get("raw_path"),
    }


def _inventory_evidence_record(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": _inventory_evidence_id(item),
        "record_type": "local_inventory",
        "host": item.get("host"),
        "observed_product": item.get("observed_product"),
        "observed_product_key": item.get("observed_product_key"),
        "observed_version": item.get("observed_version"),
        "source_type": item.get("source_type"),
    }


def _local_dns_evidence_record(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": _local_dns_evidence_id(item),
        "record_type": "local_dns_match",
        "timestamp": item.get("timestamp"),
        "host": item.get("host"),
        "queried_domain": item.get("queried_domain") or item.get("domain"),
        "query_type": item.get("query_type"),
        "match_type": item.get("match_type"),
        "threat_item_id": item.get("threat_item_id"),
        "threat_title": item.get("threat_title"),
        "threat_source": item.get("threat_source"),
        "note": item.get("note"),
    }


def _threat_evidence_id(item: dict[str, Any]) -> str:
    key = item.get("item_id") or item.get("indicator_id") or item.get("value") or item.get("title")
    return f"threat:{stable_hash(str(key))}"


def _vulnerability_evidence_id(vuln: dict[str, Any]) -> str:
    return f"vuln:{stable_hash(str(vuln.get('vuln_id') or vuln.get('title')))}"


def _inventory_evidence_id(item: dict[str, Any]) -> str:
    key = f"{item.get('host')}:{item.get('source_type')}:{item.get('observed_product')}:{item.get('observed_version')}"
    return f"inventory:{stable_hash(key)}"


def _local_dns_evidence_id(item: dict[str, Any]) -> str:
    key = f"{item.get('timestamp')}:{item.get('host')}:{item.get('queried_domain') or item.get('domain')}:{item.get('threat_item_id')}"
    return f"dns:{stable_hash(key)}"


def _sort_key(item: dict[str, Any]) -> tuple[int, str]:
    rank = {
        "local_dns_observed": 5,
        "observed_software_match": 4,
        "profile_matched": 3,
        "standard_software_watch": 2,
        "broad_high_impact": 1,
        "broad_seen_in_wild": 0,
        "context": 0,
    }
    return (rank.get(item.get("relevance_level", ""), 0), str(item.get("title", "")))
