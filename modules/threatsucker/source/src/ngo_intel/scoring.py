from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .config import load_scoring_rules
from .io_utils import read_jsonl, stable_hash, write_csv, write_jsonl
from .local_context.loader import load_local_context
from .models import (
    LocalContext,
    NormalizedIndicator,
    NormalizedVulnerability,
    ScoredIndicator,
    ScoredVulnerability,
)
from .paths import ProjectPaths


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    return value


def extract_domain_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return normalize_domain(parsed.netloc.split("@")[-1].split(":")[0])


def _indicator_domain(indicator: NormalizedIndicator | ScoredIndicator) -> str:
    if indicator.type == "url":
        return extract_domain_from_url(indicator.value)
    if indicator.type in {"domain", "hostname"}:
        return normalize_domain(indicator.value)
    return ""


def value_matches_dns(indicator: NormalizedIndicator, dns_queries: list[dict]) -> list[str]:
    domain = _indicator_domain(indicator)
    if not domain:
        return []
    matches: list[str] = []
    for row in dns_queries:
        queried = normalize_domain(str(row.get("queried_domain", "")))
        if queried == domain or queried.endswith(f".{domain}") or domain.endswith(f".{queried}"):
            host = row.get("host", "unknown-host")
            matches.append(f"dns:{host}:{queried}")
    return matches


def value_matches_brand(indicator: NormalizedIndicator, brands: list[str]) -> list[str]:
    text = " ".join([indicator.value, indicator.description or "", " ".join(indicator.tags)]).lower()
    return [brand for brand in brands if brand.lower() in text]


def priority_from_score(score: int, rules: dict) -> str:
    bands = rules.get("priority_bands", {})
    if score >= int(bands.get("critical", 90)):
        return "critical"
    if score >= int(bands.get("high", 70)):
        return "high"
    if score >= int(bands.get("medium", 45)):
        return "medium"
    if score >= int(bands.get("low", 20)):
        return "low"
    return "archive"


def _add(score: int, delta: int, key: str, detail: str, reasons: list[str]) -> int:
    sign = "+" if delta >= 0 else ""
    reasons.append(f"{sign}{delta} {key}: {detail}")
    return score + delta


def _recent_delta(indicator: NormalizedIndicator, rules: dict, reasons: list[str], score: int) -> int:
    seen = indicator.last_seen or indicator.first_seen
    if not seen:
        return score
    now = datetime.now(timezone.utc)
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    age_days = (now - seen).days
    boosts = rules.get("relevance_boosts", {})
    penalties = rules.get("penalties", {})
    if age_days <= 7:
        return _add(score, boosts.get("recent_7_days", 20), "recent_7_days", f"seen {age_days} days ago", reasons)
    if age_days <= 30:
        return _add(score, boosts.get("recent_30_days", 10), "recent_30_days", f"seen {age_days} days ago", reasons)
    if age_days > 90:
        return _add(score, penalties.get("stale_older_than_90_days", -25), "stale_older_than_90_days", f"seen {age_days} days ago", reasons)
    return score


def score_indicator(indicator: NormalizedIndicator, local_context: LocalContext, rules: dict) -> ScoredIndicator:
    score = 0
    reasons: list[str] = []
    matched: list[str] = []
    boosts = rules.get("relevance_boosts", {})
    penalties = rules.get("penalties", {})
    source_weight = int(rules.get("source_weights", {}).get(indicator.source, 0))
    score = _add(score, source_weight, "source_weight", indicator.source, reasons)

    dns_matches = value_matches_dns(indicator, local_context.dns_queries)
    if dns_matches:
        matched.extend(dns_matches)
        domain = _indicator_domain(indicator)
        score = _add(score, boosts.get("matched_dns_query", 40), "matched_dns_query", f"{domain} seen in DNS logs", reasons)

    domain = _indicator_domain(indicator)
    org_matches = [d for d in local_context.domains if domain and (domain == normalize_domain(d) or domain.endswith("." + normalize_domain(d)))]
    if org_matches:
        matched.extend([f"org_domain:{d}" for d in org_matches])
        score = _add(score, boosts.get("matched_org_domain", 35), "matched_org_domain", ", ".join(org_matches), reasons)

    brand_matches = value_matches_brand(indicator, local_context.brands_used)
    if brand_matches:
        matched.extend([f"brand:{b}" for b in brand_matches])
        score = _add(score, boosts.get("targeted_brand_used_by_org", 25), "targeted_brand_used_by_org", ", ".join(brand_matches), reasons)

    context = " ".join([indicator.value, indicator.description or "", " ".join(indicator.tags)]).lower()
    if any(token in context for token in ["luxembourg", "luxemburgish", ".lu", " lu ", "post luxembourg", "bgl bnp"]):
        matched.append("geo:luxembourg")
        score = _add(score, boosts.get("luxembourg_related", 25), "luxembourg_related", "Luxembourg context mentioned", reasons)
    if any(token in context for token in [" france", " belgium", " germany", " fr ", " be ", " de "]):
        matched.append("geo:neighbouring-country")
        score = _add(score, boosts.get("neighbouring_country_related", 10), "neighbouring_country_related", "neighbouring country context mentioned", reasons)

    threats = set(indicator.threat_type)
    if threats & {"credential_theft", "phishing"}:
        score = _add(score, boosts.get("credential_theft", 20), "credential_theft", ", ".join(sorted(threats)), reasons)
        if local_context.org_profile.technical_capacity == "low":
            score = _add(score, boosts.get("low_user_competency_environment", 15), "low_user_competency_environment", "phishing risk in low-capacity environment", reasons)
    if "ransomware" in threats:
        score = _add(score, boosts.get("ransomware", 25), "ransomware", "ransomware indicator", reasons)
    if threats & {"c2", "malware"}:
        score = _add(score, boosts.get("c2_or_malware_distribution", 25), "c2_or_malware_distribution", ", ".join(sorted(threats)), reasons)

    score = _recent_delta(indicator, rules, reasons, score)
    if indicator.confidence < 40:
        score = _add(score, penalties.get("low_confidence", -20), "low_confidence", f"confidence {indicator.confidence}", reasons)

    allowlisted = domain and domain in {normalize_domain(d) for d in local_context.allowlist_domains}
    if allowlisted:
        score = _add(score, penalties.get("allowlisted_domain", -100), "allowlisted_domain", domain, reasons)
        score = 0
        reasons.append("forced_archive allowlisted_domain: trusted local allowlist entry")

    local_or_context_match = bool(dns_matches or org_matches or brand_matches or "geo:" in " ".join(matched))
    if not local_or_context_match:
        score = _add(score, penalties.get("no_local_match", -20), "no_local_match", "no DNS, brand, org, or regional match", reasons)

    score = max(0, min(100, int(score)))
    return ScoredIndicator(
        indicator_id=indicator.indicator_id,
        score=score,
        priority=priority_from_score(score, rules),  # type: ignore[arg-type]
        type=indicator.type,
        value=indicator.value,
        source=indicator.source,
        reasons=reasons,
        matched_local_data=matched,
        recommended_actions=_indicator_actions(indicator, bool(dns_matches)),
        raw_path=indicator.raw_path,
    )


def _indicator_actions(indicator: NormalizedIndicator, matched_dns: bool) -> list[str]:
    if indicator.type in {"domain", "hostname", "url"} and ("phishing" in indicator.threat_type or "credential_theft" in indicator.threat_type):
        return [
            "Check affected host browser history",
            "Ask user whether credentials were entered",
            "Block domain at DNS resolver if confirmed malicious",
            "Review mailbox for related messages",
        ]
    if {"malware", "c2"} & set(indicator.threat_type):
        actions = ["Run endpoint scan", "Review recent downloads and persistence"]
        if matched_dns:
            actions.insert(0, "Isolate host if matched in DNS")
        return actions
    return ["Review source evidence before taking action"]


def score_vulnerability(vulnerability: NormalizedVulnerability, local_context: LocalContext, rules: dict) -> ScoredVulnerability:
    score = int(rules.get("source_weights", {}).get(vulnerability.source, 0))
    reasons = [f"+{score} source_weight: {vulnerability.source}"]
    matched_assets: list[str] = []
    boosts = rules.get("relevance_boosts", {})
    products = " ".join(json.dumps(p).lower() for p in vulnerability.affected_products)
    for row in [*local_context.software, *local_context.browsers]:
        product = str(row.get("product") or row.get("browser") or "").lower()
        if product and product in products:
            matched_assets.append(f"{row.get('host', 'unknown-host')}:{product}")
    if matched_assets:
        score = _add(score, boosts.get("matched_asset_software", 40), "matched_asset_software", ", ".join(matched_assets), reasons)
    if vulnerability.exploit_available:
        score = _add(score, boosts.get("exploit_available", 20), "exploit_available", vulnerability.vuln_id, reasons)
    if vulnerability.known_exploited:
        score = _add(score, boosts.get("known_exploited", 35), "known_exploited", vulnerability.vuln_id, reasons)
    if not matched_assets:
        score = _add(score, rules.get("penalties", {}).get("no_local_match", -20), "no_local_match", "no affected local software found", reasons)
    score = max(0, min(100, int(score)))
    return ScoredVulnerability(
        vuln_id=vulnerability.vuln_id,
        score=score,
        priority=priority_from_score(score, rules),  # type: ignore[arg-type]
        title=vulnerability.title,
        matched_assets=matched_assets,
        reasons=reasons,
        recommended_actions=["Patch matched software", "Prioritize public-facing services", "Verify installed versions"],
        raw_path=vulnerability.raw_path,
    )


def score_all(paths: ProjectPaths, date: datetime | None = None) -> tuple[list[ScoredIndicator], list[ScoredVulnerability]]:
    rules = load_scoring_rules(paths.config_dir / "scoring_rules.yaml")
    local_context = load_local_context(paths)
    norm_dir = paths.normalized_date_dir(date)
    scored_dir = paths.scored_date_dir(date)
    indicators = read_jsonl(norm_dir / "indicators.jsonl", NormalizedIndicator)
    vulnerabilities = read_jsonl(norm_dir / "vulnerabilities.jsonl", NormalizedVulnerability)
    scored_indicators = [score_indicator(item, local_context, rules) for item in indicators]
    scored_vulns = [score_vulnerability(item, local_context, rules) for item in vulnerabilities]
    relevant_indicators = [item for item in scored_indicators if item.priority != "archive"]
    dns_matches = [item for item in scored_indicators if any(match.startswith("dns:") for match in item.matched_local_data)]
    write_jsonl(scored_dir / "relevant_indicators.jsonl", relevant_indicators)
    write_csv(scored_dir / "relevant_indicators.csv", relevant_indicators)
    write_jsonl(scored_dir / "relevant_vulnerabilities.jsonl", [v for v in scored_vulns if v.priority != "archive"])
    write_csv(scored_dir / "relevant_vulnerabilities.csv", [v for v in scored_vulns if v.priority != "archive"])
    write_csv(scored_dir / "dns_matches.csv", dns_matches)
    risk_items = [
        {
            "risk_id": stable_hash(item.indicator_id),
            "title": f"{item.priority.title()} indicator: {item.value}",
            "risk_type": "indicator",
            "priority": item.priority if item.priority != "archive" else "low",
            "score": item.score,
            "why_relevant": item.reasons,
            "evidence": [{"indicator_id": item.indicator_id, "raw_path": item.raw_path}],
            "recommended_actions": item.recommended_actions,
            "agent_summary": f"{item.value} scored {item.score} because: {item.reasons[0] if item.reasons else 'no reasons'}",
        }
        for item in relevant_indicators
        if item.priority in {"medium", "high", "critical"}
    ]
    write_jsonl(scored_dir / "risk_items.jsonl", risk_items)
    return scored_indicators, scored_vulns
