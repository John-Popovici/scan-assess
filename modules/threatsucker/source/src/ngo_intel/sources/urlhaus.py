from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ngo_intel.io_utils import stable_hash
from ngo_intel.models import NormalizedIndicator


def parse_urlhaus_jsonl(path: str | Path) -> list[NormalizedIndicator]:
    path = Path(path)
    indicators: list[NormalizedIndicator] = []
    if not path.exists():
        return indicators
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            indicators.append(normalize_urlhaus_record(record, str(path)))
    return indicators


def normalize_urlhaus_record(record: dict[str, Any], raw_path: str | None = None) -> NormalizedIndicator:
    url = str(record.get("url") or record.get("urlhaus_reference") or "").strip()
    status = str(record.get("url_status", record.get("status", "online"))).lower()
    source = "urlhaus_online" if status == "online" else "urlhaus_offline"
    tags = [str(t) for t in record.get("tags", []) if t]
    threat_type = ["malware"]
    if "c2" in " ".join(tags).lower():
        threat_type.append("c2")
    return NormalizedIndicator(
        indicator_id=stable_hash(f"{source}:url:{url}"),
        source=source,
        source_ref=str(record.get("id") or record.get("urlhaus_reference") or ""),
        first_seen=_parse_dt(record.get("date_added") or record.get("dateadded")),
        last_seen=_parse_dt(record.get("last_online")),
        type="url",
        value=url,
        normalized_value=url,
        category="malware-distribution",
        threat_type=threat_type,
        malware_family=record.get("threat"),
        tags=tags,
        confidence=75 if status == "online" else 55,
        severity="high" if status == "online" else "medium",
        description=str(record.get("threat") or "URLhaus malware URL"),
        raw_path=raw_path,
    )


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00").replace(" UTC", "+00:00")
        return datetime.fromisoformat(text)
    except ValueError:
        return None
