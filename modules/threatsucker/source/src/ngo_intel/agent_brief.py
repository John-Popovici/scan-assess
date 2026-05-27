from __future__ import annotations

import json
from datetime import datetime, timezone

from .io_utils import read_jsonl, stable_hash, write_csv
from .local_context.loader import load_local_context
from .models import RiskItem, ScoredIndicator, ScoredVulnerability
from .paths import ProjectPaths


def _priority_rank(priority: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "archive": 0}.get(priority, 0)


def generate_agent_context(paths: ProjectPaths, date: datetime | None = None) -> None:
    scored_dir = paths.scored_date_dir(date)
    out_dir = paths.agent_context_dir / "current"
    out_dir.mkdir(parents=True, exist_ok=True)
    local_context = load_local_context(paths)
    indicators = read_jsonl(scored_dir / "relevant_indicators.jsonl", ScoredIndicator)
    vulnerabilities = read_jsonl(scored_dir / "relevant_vulnerabilities.jsonl", ScoredVulnerability)
    indicators = sorted(indicators, key=lambda item: (item.score, _priority_rank(item.priority)), reverse=True)
    vulnerabilities = sorted(vulnerabilities, key=lambda item: item.score, reverse=True)
    top_indicators = [item for item in indicators if item.priority in {"medium", "high", "critical"}][:20]
    top_vulns = [item for item in vulnerabilities if item.priority in {"medium", "high", "critical"}][:20]
    dns_matches = [item for item in indicators if any(m.startswith("dns:") for m in item.matched_local_data)]

    risk_items: list[RiskItem] = []
    for item in top_indicators[:10]:
        risk_items.append(
            RiskItem(
                risk_id=stable_hash(item.indicator_id),
                title=f"{item.priority.title()} suspicious indicator: {item.value}",
                risk_type="indicator",
                priority=item.priority,  # type: ignore[arg-type]
                score=item.score,
                why_relevant=item.reasons[:8],
                evidence=[{"indicator_id": item.indicator_id, "source": item.source, "raw_path": item.raw_path}],
                recommended_actions=item.recommended_actions,
                agent_summary=f"{item.value} is relevant because it scored {item.score} with local/context matches where available.",
            )
        )

    write_csv(out_dir / "top_indicators.csv", top_indicators)
    write_csv(out_dir / "top_vulnerabilities.csv", top_vulns)
    write_csv(out_dir / "dns_matches.csv", dns_matches)
    (out_dir / "top_threats.json").write_text(json.dumps([r.model_dump(mode="json") for r in risk_items], indent=2), encoding="utf-8")
    (out_dir / "action_queue.json").write_text(
        json.dumps(
            [
                {"priority": item.priority, "item": item.value, "actions": item.recommended_actions}
                for item in top_indicators[:10]
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    (out_dir / "evidence_index.json").write_text(
        json.dumps(
            {
                "normalized_indicators": str(paths.normalized_date_dir(date) / "indicators.jsonl"),
                "scored_indicators": str(scored_dir / "relevant_indicators.jsonl"),
                "raw_paths": sorted({item.raw_path for item in top_indicators if item.raw_path}),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (out_dir / "intel_brief.md").write_text(_render_brief(local_context.org_profile.country, top_indicators, top_vulns, dns_matches, len(indicators) - len(top_indicators)), encoding="utf-8")


def _render_brief(country: str, indicators: list[ScoredIndicator], vulns: list[ScoredVulnerability], dns_matches: list[ScoredIndicator], excluded: int) -> str:
    generated = datetime.now(timezone.utc).isoformat()
    lines = [
        "# NGO Threat Intel Brief",
        "",
        f"Generated: {generated}",
        f"Organization country: {country}",
        "Data window: last 7 days",
        "",
        "## Executive Summary",
        "",
        f"{len(indicators)} medium-or-higher indicators and {len(vulns)} relevant vulnerabilities were retained for analyst and agent review. Raw evidence is preserved separately; this brief contains only reduced triage intelligence.",
        "",
        "## Top Risks",
        "",
    ]
    for item in indicators[:10]:
        lines.extend(
            [
                f"- Priority: {item.priority} ({item.score})",
                f"  - Why this matters: {'; '.join(item.reasons[:4])}",
                f"  - Evidence: {item.indicator_id}; raw={item.raw_path}",
                f"  - Recommended actions: {'; '.join(item.recommended_actions)}",
            ]
        )
    if not indicators:
        lines.append("- No medium-or-higher indicators were retained.")
    lines.extend(["", "## Notable DNS Matches", ""])
    for item in dns_matches[:10]:
        lines.append(f"- {item.value} matched {', '.join(item.matched_local_data)}")
    if not dns_matches:
        lines.append("- No suspicious DNS matches were found.")
    lines.extend(["", "## Vulnerabilities Relevant to Observed Assets", ""])
    for vuln in vulns[:10]:
        lines.append(f"- {vuln.vuln_id} ({vuln.priority}, {vuln.score}): {vuln.title}; matched {', '.join(vuln.matched_assets) or 'no specific asset'}")
    if not vulns:
        lines.append("- No matched vulnerabilities were retained.")
    lines.extend(["", "## Items intentionally excluded", "", f"- {max(excluded, 0)} low-score or archive items were excluded from this compact agent brief. Inspect scored CSV/JSONL outputs for the full triage list."])
    return "\n".join(lines) + "\n"
