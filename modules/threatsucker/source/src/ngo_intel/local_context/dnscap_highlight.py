from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ngo_intel.io_utils import read_jsonl, write_csv, write_jsonl
from ngo_intel.local_context.dns import normalize_domain, read_dnscap_tree
from ngo_intel.paths import ProjectPaths


def load_watch_domains(path: str | Path) -> list[dict[str, str]]:
    """Load domains from mini threat_items JSONL/CSV-like JSON records.

    The watch list is intentionally simple: domains extracted during mini mode
    are enough to highlight local DNS evidence without scoring.
    """
    records = read_jsonl(path)
    domains: list[dict[str, str]] = []
    for record in records:
        domain = normalize_domain(str(record.get("domain", "")))
        if not domain:
            continue
        domains.append(
            {
                "domain": domain,
                "title": str(record.get("title", "")),
                "source": str(record.get("source", "")),
                "item_id": str(record.get("item_id", "")),
                "threat_type": json.dumps(record.get("threat_type", []), separators=(",", ":")),
            }
        )
    return _dedupe_domains(domains)


def highlight_dnscap(
    dns_path: str | Path,
    watch_items_path: str | Path,
    out_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    dns_rows = read_dnscap_tree(dns_path)
    watch_domains = load_watch_domains(watch_items_path)
    highlights: list[dict[str, Any]] = []

    for row in dns_rows:
        queried = normalize_domain(str(row.get("queried_domain", "")))
        if not queried:
            continue
        for watch in watch_domains:
            watched = watch["domain"]
            if queried == watched or queried.endswith(f".{watched}"):
                highlights.append(
                    {
                        "timestamp": row.get("timestamp", ""),
                        "host": row.get("host", ""),
                        "queried_domain": queried,
                        "query_type": row.get("query_type", ""),
                        "matched_domain": watched,
                        "match_type": "exact" if queried == watched else "subdomain",
                        "source": row.get("source", "dns"),
                        "src_ip": row.get("src_ip", ""),
                        "dst_ip": row.get("dst_ip", ""),
                        "threat_item_id": watch.get("item_id", ""),
                        "threat_title": watch.get("title", ""),
                        "threat_source": watch.get("source", ""),
                        "note": "DNS query observed for a profile-matched threat domain; this is evidence of lookup, not proof credentials were entered.",
                    }
                )

    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        write_jsonl(out_path / "dnscap_highlights.jsonl", highlights)
        write_csv(out_path / "dnscap_highlights.csv", highlights)
        (out_path / "dnscap_highlights.md").write_text(render_dnscap_highlights(highlights), encoding="utf-8")
    return highlights


def highlight_current_mini(paths: ProjectPaths, dns_path: str | Path | None = None) -> list[dict[str, Any]]:
    mini_dir = paths.data_dir / "mini" / "current"
    dns = Path(dns_path) if dns_path else paths.local_context_dir / "dns" / "current" / "queries.csv"
    return highlight_dnscap(dns, mini_dir / "threat_items.jsonl", mini_dir)


def render_dnscap_highlights(highlights: list[dict[str, Any]]) -> str:
    lines = [
        "# DNScap Highlights",
        "",
        "These rows show DNS queries that matched domains from the current ThreatSucker mini context pack. Treat them as lookup evidence, not proof of a completed website visit or compromise.",
        "",
    ]
    if not highlights:
        lines.append("No DNScap DNS queries matched the current mini threat domains.")
        return "\n".join(lines) + "\n"

    for item in highlights:
        lines.extend(
            [
                f"## {item.get('queried_domain')}",
                "",
                f"- Time: {item.get('timestamp')}",
                f"- Host: {item.get('host')}",
                f"- Matched threat item: {item.get('threat_title')}",
                f"- Match type: {item.get('match_type')}",
                f"- Note: {item.get('note')}",
                "",
            ]
        )
    return "\n".join(lines)


def _dedupe_domains(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for row in rows:
        domain = row["domain"]
        if domain in seen:
            continue
        seen.add(domain)
        deduped.append(row)
    return deduped
