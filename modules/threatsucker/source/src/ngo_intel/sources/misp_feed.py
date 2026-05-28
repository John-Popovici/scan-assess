from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ngo_intel.io_utils import stable_hash
from ngo_intel.models import NormalizedIndicator
from ngo_intel.scoring import normalize_domain


MISP_TYPE_MAP = {
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "ip-src": "ip",
    "ip-dst": "ip",
    "email-src": "email",
    "email-dst": "email",
    "email-subject": "text",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "vulnerability": "cve",
    "text": "text",
}


def _dt_from_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _tag_names(items: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("name", "")).strip() for item in items if item.get("name")]


def _infer_threat_type(text: str) -> list[str]:
    lowered = text.lower()
    threats: list[str] = []
    if any(word in lowered for word in ["phishing", "credential", "login"]):
        threats.append("phishing")
        if "credential" in lowered or "login" in lowered:
            threats.append("credential_theft")
    if "ransomware" in lowered:
        threats.append("ransomware")
    if any(word in lowered for word in ["malware", "trojan", "loader", "botnet"]):
        threats.append("malware")
    if "c2" in lowered or "command and control" in lowered:
        threats.append("c2")
    return list(dict.fromkeys(threats))


def _normalize_value(indicator_type: str, value: str) -> str:
    value = value.strip()
    if indicator_type in {"domain", "hostname"}:
        return normalize_domain(value)
    if indicator_type == "url":
        return value.strip()
    if indicator_type in {"email", "hash", "cve"}:
        return value.lower()
    return value


def normalize_misp_event(event: dict[str, Any], raw_path: str | None = None) -> list[NormalizedIndicator]:
    event_data = event.get("Event", event)
    event_uuid = str(event_data.get("uuid", "unknown-event"))
    event_info = str(event_data.get("info", ""))
    event_tags = _tag_names(event_data.get("Tag", []))
    event_seen = _dt_from_timestamp(event_data.get("timestamp"))
    indicators: list[NormalizedIndicator] = []

    for attribute in event_data.get("Attribute", []):
        misp_type = str(attribute.get("type", "text"))
        mapped_type = MISP_TYPE_MAP.get(misp_type, "text")
        raw_value = str(attribute.get("value", "")).strip()
        if not raw_value:
            continue
        if misp_type == "vulnerability" and not raw_value.upper().startswith("CVE-"):
            mapped_type = "text"
        normalized_value = _normalize_value(mapped_type, raw_value)
        attribute_uuid = str(attribute.get("uuid", "unknown-attribute"))
        tags = [*event_tags, *_tag_names(attribute.get("Tag", []))]
        context = " ".join([event_info, str(attribute.get("comment", "")), " ".join(tags)])
        indicator_id = stable_hash(f"misp_osint:{mapped_type}:{normalized_value}")
        indicators.append(
            NormalizedIndicator(
                indicator_id=indicator_id,
                source="misp_osint",
                source_ref=f"misp:{event_uuid}:{attribute_uuid}",
                first_seen=event_seen,
                last_seen=_dt_from_timestamp(attribute.get("timestamp")) or event_seen,
                type=mapped_type,  # type: ignore[arg-type]
                value=raw_value,
                normalized_value=normalized_value,
                category=attribute.get("category"),
                threat_type=_infer_threat_type(context),
                tags=tags,
                confidence=80 if attribute.get("to_ids") else 55,
                severity="high" if any(t in context.lower() for t in ["ransomware", "credential"]) else "medium",
                description=str(attribute.get("comment") or event_info),
                raw_path=raw_path,
            )
        )
    return indicators
