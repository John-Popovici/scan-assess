from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ngo_intel.io_utils import stable_hash
from ngo_intel.models import NormalizedIndicator
from ngo_intel.scoring import extract_domain_from_url


def parse_phishtank_lookup(path: str | Path) -> list[NormalizedIndicator]:
    path = Path(path)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("results")
    if isinstance(records, dict):
        records = [records]
    return [normalize_phishtank_record(record, str(path)) for record in records or [] if record.get("url")]


def normalize_phishtank_record(record: dict[str, Any], raw_path: str | None = None) -> NormalizedIndicator:
    url = str(record.get("url", "")).strip()
    verified = bool(record.get("verified"))
    source = "phishtank_verified" if verified else "phishtank_unverified"
    domain = extract_domain_from_url(url)
    return NormalizedIndicator(
        indicator_id=stable_hash(f"{source}:url:{url}"),
        source=source,
        source_ref=str(record.get("phish_id", "")),
        first_seen=None,
        last_seen=None,
        type="url",
        value=url,
        normalized_value=url,
        category="phishing",
        threat_type=["phishing", "credential_theft"],
        tags=["phishtank", "verified" if verified else "unverified"],
        confidence=85 if verified else 45,
        severity="high" if verified else "medium",
        description=f"PhishTank phishing URL for {domain}" if domain else "PhishTank phishing URL",
        raw_path=raw_path,
    )
