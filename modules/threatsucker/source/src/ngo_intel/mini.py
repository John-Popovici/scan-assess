from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import re

from .config import load_yaml
from .io_utils import stable_hash, write_csv, write_jsonl
from .models import MiniProfile, NormalizedIndicator, NormalizedVulnerability
from .normalize import normalize_all
from .paths import ProjectPaths
from .scoring import extract_domain_from_url, normalize_domain


def load_mini_profile(paths: ProjectPaths, profile_id: str = "luxembourg_ngo") -> MiniProfile:
    path = paths.config_dir / "profiles" / f"{profile_id}.yaml"
    return MiniProfile.model_validate(load_yaml(path))


def list_mini_profiles(paths: ProjectPaths) -> list[MiniProfile]:
    profile_dir = paths.config_dir / "profiles"
    if not profile_dir.exists():
        return []
    return [MiniProfile.model_validate(load_yaml(path)) for path in sorted(profile_dir.glob("*.yaml"))]


def run_mini(paths: ProjectPaths, profile_id: str = "luxembourg_ngo") -> dict[str, int]:
    profile = load_mini_profile(paths, profile_id)
    indicators, vulnerabilities = normalize_all(paths)
    items = build_mini_items(profile, indicators, vulnerabilities)
    out_dir = paths.data_dir / "mini" / "current"
    out_dir.mkdir(parents=True, exist_ok=True)

    limited_items = items[: profile.output_limit]
    write_jsonl(out_dir / "threat_items.jsonl", limited_items)
    write_csv(out_dir / "threat_items.csv", limited_items)
    write_csv(out_dir / "domains.csv", [item for item in limited_items if item.get("indicator_type") in {"domain", "hostname"}])
    write_csv(out_dir / "urls.csv", [item for item in limited_items if item.get("indicator_type") == "url"])
    write_csv(out_dir / "vulnerabilities.csv", [item for item in limited_items if item.get("kind") == "vulnerability"])
    (out_dir / "profile.json").write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    (out_dir / "ai_context.md").write_text(render_mini_context(profile, limited_items, len(items)), encoding="utf-8")
    (out_dir / "ai_context.json").write_text(
        json.dumps(build_mini_context_json(profile, limited_items, len(items)), indent=2),
        encoding="utf-8",
    )
    (out_dir / "evidence_index.json").write_text(
        json.dumps(
            {
                "profile": profile.profile_id,
                "generated": datetime.now(timezone.utc).isoformat(),
                "raw_paths": sorted({item["evidence_path"] for item in limited_items if item.get("evidence_path")}),
                "normalized_indicators": str(paths.normalized_date_dir() / "indicators.jsonl"),
                "normalized_vulnerabilities": str(paths.normalized_date_dir() / "vulnerabilities.jsonl"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "normalized_indicators": len(indicators),
        "normalized_vulnerabilities": len(vulnerabilities),
        "included_items": len(limited_items),
        "candidate_items": len(items),
    }


def build_mini_items(
    profile: MiniProfile,
    indicators: list[NormalizedIndicator],
    vulnerabilities: list[NormalizedVulnerability],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for indicator in indicators:
        reasons = indicator_inclusion_reasons(profile, indicator)
        if reasons:
            items.append(_indicator_item(profile, indicator, reasons))
    for vulnerability in vulnerabilities:
        reasons = vulnerability_inclusion_reasons(profile, vulnerability)
        if reasons:
            items.append(_vulnerability_item(vulnerability, reasons))
    return sorted(items, key=_mini_sort_key, reverse=True)


def indicator_inclusion_reasons(profile: MiniProfile, indicator: NormalizedIndicator) -> list[str]:
    reasons: list[str] = []
    text = _indicator_text(indicator)
    source_allowed = not profile.include_sources or indicator.source in profile.include_sources
    if not source_allowed:
        return []
    if indicator.type not in profile.high_impact_indicator_types:
        return []
    reasons.append(f"high_impact_indicator_type: {indicator.type}")
    for threat in indicator.threat_type:
        if _contains_term(threat, profile.threat_focus):
            reasons.append(f"threat_focus: {threat}")
    for label, terms in [
        ("country_term", profile.country_terms),
        ("neighbouring_country_term", profile.neighbouring_country_terms),
        ("sector_term", profile.sector_terms),
        ("brand_term", profile.brand_terms),
    ]:
        matches = _matched_terms(text, terms)
        if matches:
            reasons.append(f"{label}: {', '.join(matches[:3])}")
    return list(dict.fromkeys(reasons))


def vulnerability_inclusion_reasons(profile: MiniProfile, vulnerability: NormalizedVulnerability) -> list[str]:
    text = " ".join(
        [
            vulnerability.vuln_id,
            vulnerability.title,
            vulnerability.description or "",
            json.dumps(vulnerability.affected_products, ensure_ascii=False),
        ]
    ).lower()
    reasons: list[str] = []
    if "vulnerability" in profile.threat_focus:
        reasons.append("threat_focus: vulnerability")
    brand_matches = _matched_terms(text, profile.brand_terms)
    if brand_matches:
        reasons.append(f"brand_term: {', '.join(brand_matches[:3])}")
    if vulnerability.exploit_available:
        reasons.append("impact_signal: exploit_available")
    if vulnerability.known_exploited:
        reasons.append("impact_signal: known_exploited")
    if vulnerability.cvss is not None and vulnerability.cvss >= 8:
        reasons.append(f"impact_signal: cvss {vulnerability.cvss}")
    return list(dict.fromkeys(reasons))


def render_mini_context(profile: MiniProfile, items: list[dict[str, Any]], candidate_count: int) -> str:
    generated = datetime.now(timezone.utc).isoformat()
    lines = [
        "# ThreatSucker Mini Context",
        "",
        f"Generated: {generated}",
        f"Profile: {profile.name} ({profile.profile_id})",
        "Mode: mini/basic, no scoring",
        "",
        "## Purpose",
        "",
        "This pack contains compact, profile-matched threat information for an AI assistant. Items are included because they match simple profile terms or high-impact categories; no numeric scoring or local personalization has been applied.",
        "",
        "## Profile Focus",
        "",
        f"- Threats: {', '.join(profile.threat_focus)}",
        f"- Brands/themes: {', '.join(profile.brand_terms)}",
        f"- Regional terms: {', '.join(profile.country_terms)}",
        "",
        "## Included Threat Items",
        "",
    ]
    for item in items:
        lines.extend(
            [
                f"### {item['title']}",
                "",
                f"- Kind: {item['kind']}",
                f"- Source: {item['source']}",
                f"- Value: {item.get('value', item.get('vuln_id', ''))}",
                f"- Filtering rules used: {_theme_rule_summary(item)}",
                f"- Inclusion reasons: {'; '.join(item['include_reasons'])}",
                f"- Evidence: {item.get('evidence_path') or 'normalized source record'}",
                f"- Suggested AI use: {item['suggested_ai_use']}",
                "",
            ]
        )
    if not items:
        lines.append("No profile-matched threat items were found.")
        lines.append("")
    lines.extend(
        [
            "## Excluded Material",
            "",
            f"{max(candidate_count - len(items), 0)} candidate items were omitted by the output limit or profile filtering.",
            "",
            "## Important Boundary",
            "",
            "This mini pack is not a decision, risk score, or attribution claim. It is source/context material for a later AI reasoning step.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_mini_context_json(profile: MiniProfile, items: list[dict[str, Any]], candidate_count: int) -> dict[str, Any]:
    return {
        "title": "ThreatSucker Mini Context",
        "generated": datetime.now(timezone.utc).isoformat(),
        "profile": {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "description": profile.description,
            "threat_focus": profile.threat_focus,
            "brand_terms": profile.brand_terms,
            "country_terms": profile.country_terms,
            "theme_rules": profile.theme_rules,
        },
        "mode": "mini/basic",
        "scoring_applied": False,
        "purpose": "Compact profile-matched threat information for an AI assistant.",
        "included_items": items,
        "excluded_material": {
            "candidate_items": candidate_count,
            "output_limit": profile.output_limit,
            "omitted_by_limit_or_filter": max(candidate_count - len(items), 0),
        },
        "boundary": [
            "This mini pack is not a decision, risk score, or attribution claim.",
            "Filtering rules explain why an item was retained; they do not prove local targeting.",
            "Use DNS, asset, browser, and user-context evidence separately for local relevance.",
        ],
    }


def _indicator_item(profile: MiniProfile, indicator: NormalizedIndicator, reasons: list[str]) -> dict[str, Any]:
    value = indicator.value
    domain = extract_domain_from_url(value) if indicator.type == "url" else normalize_domain(value) if indicator.type in {"domain", "hostname"} else ""
    theme_matches = _matched_theme_rules(profile, _indicator_text(indicator), indicator.threat_type)
    return {
        "item_id": stable_hash(f"mini:{indicator.indicator_id}"),
        "kind": "indicator",
        "title": f"{indicator.type}: {value}",
        "indicator_id": indicator.indicator_id,
        "indicator_type": indicator.type,
        "value": value,
        "domain": domain,
        "source": indicator.source,
        "threat_type": indicator.threat_type,
        "theme_matches": theme_matches,
        "include_reasons": reasons,
        "relevance_level": _relevance_level(indicator.source, reasons),
        "description": indicator.description,
        "tags": indicator.tags,
        "evidence_path": indicator.raw_path,
        "suggested_ai_use": _indicator_suggested_use(indicator),
    }


def _vulnerability_item(vulnerability: NormalizedVulnerability, reasons: list[str]) -> dict[str, Any]:
    return {
        "item_id": stable_hash(f"mini:{vulnerability.vuln_id}"),
        "kind": "vulnerability",
        "title": vulnerability.title,
        "vuln_id": vulnerability.vuln_id,
        "source": vulnerability.source,
        "include_reasons": reasons,
        "relevance_level": _relevance_level(vulnerability.source, reasons),
        "affected_products": vulnerability.affected_products,
        "cvss": vulnerability.cvss,
        "exploit_available": vulnerability.exploit_available,
        "known_exploited": vulnerability.known_exploited,
        "evidence_path": vulnerability.raw_path,
        "suggested_ai_use": "Use as general vulnerability context; only personalize if matching asset/software data is supplied later.",
    }


def _indicator_suggested_use(indicator: NormalizedIndicator) -> str:
    threats = set(indicator.threat_type)
    if indicator.type == "cve":
        return "Use as vulnerability context mentioned by a source; verify against real affected software before advising action."
    if threats & {"phishing", "credential_theft"}:
        return "Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review."
    if threats & {"malware", "c2"}:
        return "Use as malware-delivery context; only escalate if later local telemetry observes the domain or URL."
    return "Use as profile-matched threat context, not as proof of local compromise."


def _matched_theme_rules(profile: MiniProfile, text: str, threat_types: list[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    normalized_threats = {threat.lower().replace("-", "_") for threat in threat_types}
    for rule in profile.theme_rules:
        rule_threats = {str(threat).lower().replace("-", "_") for threat in rule.get("threat_focus", [])}
        rule_terms = [str(term) for term in rule.get("terms", [])]
        matched_terms = _matched_terms(text, rule_terms)
        threat_match = bool(normalized_threats & rule_threats) if rule_threats else True
        if threat_match and matched_terms:
            matches.append(
                {
                    "id": rule.get("id", "unnamed_theme"),
                    "label": rule.get("label", rule.get("id", "Unnamed theme")),
                    "matched_terms": matched_terms,
                    "broad_context_only": bool(rule.get("broad_context_only", False)),
                    "suggested_ai_use": rule.get("suggested_ai_use"),
                }
            )
    return matches


def _theme_rule_summary(item: dict[str, Any]) -> str:
    summaries: list[str] = []
    for theme in item.get("theme_matches", []):
        rule_id = str(theme.get("id") or "unnamed_theme")
        label = str(theme.get("label") or rule_id)
        terms = ", ".join(str(term) for term in theme.get("matched_terms", [])) or "no terms recorded"
        scope = "broad context only" if theme.get("broad_context_only") else "profile relevance"
        summaries.append(f"{rule_id} ({label}; matched: {terms}; scope: {scope})")
    return "; ".join(summaries) if summaries else "none"


def _indicator_text(indicator: NormalizedIndicator) -> str:
    return " ".join(
        [
            indicator.value,
            indicator.normalized_value,
            indicator.description or "",
            indicator.category or "",
            " ".join(indicator.threat_type),
            " ".join(indicator.tags),
        ]
    ).lower()


def _contains_term(value: str, terms: list[str]) -> bool:
    lowered = value.lower().replace("-", "_")
    return any(term.lower().replace("-", "_") in lowered for term in terms)


def _matched_terms(text: str, terms: list[str]) -> list[str]:
    lowered = text.lower()
    matches: list[str] = []
    for term in terms:
        term_lower = term.lower()
        if _term_matches(lowered, term_lower):
            matches.append(term)
    return matches


def _term_matches(text: str, term: str) -> bool:
    if term == ".lu":
        return ".lu" in text
    if len(term) <= 2:
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None
    return term in text


def _relevance_level(source: str, reasons: list[str]) -> str:
    joined = " ".join(reasons)
    if "brand_term" in joined or "sector_term" in joined or "country_term" in joined:
        return "profile_matched"
    if source.startswith("urlhaus"):
        return "broad_seen_in_wild"
    if "impact_signal" in joined:
        return "broad_high_impact"
    return "context"


def _mini_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    kind_rank = 1 if item.get("kind") == "indicator" else 0
    reason_rank = len(item.get("include_reasons", []))
    return (reason_rank, kind_rank, item.get("title", ""))
