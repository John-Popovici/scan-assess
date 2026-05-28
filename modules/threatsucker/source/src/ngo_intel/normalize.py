from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .config import load_source_config
from .io_utils import write_csv, write_jsonl
from .models import NormalizedIndicator, NormalizedVulnerability
from .paths import ProjectPaths
from .sources.misp_feed import normalize_misp_event
from .sources.phishtank import parse_phishtank_lookup
from .sources.urlhaus import parse_urlhaus_jsonl
from .sources.vulnerability_lookup import parse_vulnerability_jsonl

NORMALIZE_SOURCE_CONFIG_KEYS = {
    "misp": "misp_osint",
    "urlhaus": "urlhaus",
    "phishtank": "phishtank",
    "vulnerability_lookup": "circl_vulnerability_lookup",
}


def _candidate_files(
    paths: ProjectPaths,
    source: str,
    date: datetime | None,
    patterns: list[str],
    *,
    allow_fixtures: bool = False,
) -> list[Path]:
    raw_candidates: list[Path] = []
    for base in [paths.raw_dir / source, paths.raw_source_date_dir(source, date)]:
        if base.exists():
            for pattern in patterns:
                raw_candidates.extend(sorted(base.glob(pattern)))
    if raw_candidates:
        return _unique_existing(raw_candidates)

    if not allow_fixtures:
        return []

    candidates: list[Path] = []
    fixture_dir = paths.project_root / "tests" / "fixtures"
    if fixture_dir.exists():
        fixture_patterns = {
            "misp": ["misp_event_sample.json"],
            "urlhaus": ["urlhaus_sample.jsonl"],
            "phishtank": ["phishtank_lookup_sample.json"],
            "vulnerability_lookup": ["vulnerability_lookup_sample.jsonl"],
        }
        for pattern in fixture_patterns.get(source, []):
            candidates.extend(sorted(fixture_dir.glob(pattern)))
    return _unique_existing(candidates)


def _unique_existing(candidates: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for item in candidates:
        resolved = item.resolve()
        if resolved not in seen and item.exists():
            seen.add(resolved)
            unique.append(item)
    return unique


def normalize_all(paths: ProjectPaths, date: datetime | None = None) -> tuple[list[NormalizedIndicator], list[NormalizedVulnerability]]:
    indicators: list[NormalizedIndicator] = []
    vulnerabilities: list[NormalizedVulnerability] = []
    source_config = load_source_config(paths.config_dir / "source_config.yaml").get("sources", {})

    def source_enabled(raw_source: str) -> bool:
        config_key = NORMALIZE_SOURCE_CONFIG_KEYS.get(raw_source, raw_source)
        return bool(source_config.get(config_key, {}).get("enabled", True))

    def source_allows_fixtures(raw_source: str) -> bool:
        config_key = NORMALIZE_SOURCE_CONFIG_KEYS.get(raw_source, raw_source)
        mode = str(source_config.get(config_key, {}).get("mode", ""))
        return "fixture" in mode

    if source_enabled("misp"):
        for path in _candidate_files(paths, "misp", date, ["*.json"], allow_fixtures=source_allows_fixtures("misp")):
            data = json.loads(path.read_text(encoding="utf-8"))
            indicators.extend(normalize_misp_event(data, str(path)))

    if source_enabled("urlhaus"):
        for path in _candidate_files(paths, "urlhaus", date, ["*.jsonl"], allow_fixtures=source_allows_fixtures("urlhaus")):
            indicators.extend(parse_urlhaus_jsonl(path))

    if source_enabled("phishtank"):
        for path in _candidate_files(paths, "phishtank", date, ["*.json"], allow_fixtures=source_allows_fixtures("phishtank")):
            indicators.extend(parse_phishtank_lookup(path))

    if source_enabled("vulnerability_lookup"):
        for path in _candidate_files(
            paths,
            "vulnerability_lookup",
            date,
            ["*.jsonl"],
            allow_fixtures=source_allows_fixtures("vulnerability_lookup"),
        ):
            vulnerabilities.extend(parse_vulnerability_jsonl(path))

    out_dir = paths.normalized_date_dir(date)
    write_jsonl(out_dir / "indicators.jsonl", indicators)
    write_csv(out_dir / "indicators.csv", indicators)
    write_jsonl(out_dir / "vulnerabilities.jsonl", vulnerabilities)
    write_csv(out_dir / "vulnerabilities.csv", vulnerabilities)
    return indicators, vulnerabilities
