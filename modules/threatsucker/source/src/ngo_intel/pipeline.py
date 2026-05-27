from __future__ import annotations

from pathlib import Path
from typing import Any

from .live_collect import collect_live_sources
from .local_context.dnscap_highlight import highlight_current_mini
from .local_context.enumeros_filter import filter_enumeros_documents
from .local_context.importers import import_enumeros_json, import_safesniff_json
from .mini import run_mini
from .ngo_brief import build_ngo_relevance_brief
from .overview import build_overview
from .paths import ProjectPaths


DEFAULT_PROFILE = "luxembourg_ngo"


def project_paths(project_root: str | Path | None = None) -> ProjectPaths:
    """Resolve ThreatSucker paths for CLI or external callers."""
    return ProjectPaths.discover(project_root)


def build_mini_pack(
    project_root: str | Path | None = None,
    profile_id: str = DEFAULT_PROFILE,
    include_relevance_brief: bool = True,
) -> dict[str, Any]:
    """Build the default no-scoring AI context pack.

    External software can call this instead of shelling out to
    ``threatsucker mini run``. It returns counts and output locations.
    """
    paths = project_paths(project_root)
    mini_counts = run_mini(paths, profile_id)
    result: dict[str, Any] = {
        "profile_id": profile_id,
        "mini_counts": mini_counts,
        "output_dir": str(paths.data_dir / "mini" / "current"),
        "ai_context_md": str(paths.data_dir / "mini" / "current" / "ai_context.md"),
        "ai_context_json": str(paths.data_dir / "mini" / "current" / "ai_context.json"),
    }
    if include_relevance_brief:
        result["relevance_counts"] = build_ngo_relevance_brief(paths)
        result["relevance_brief_md"] = str(paths.data_dir / "mini" / "current" / "ngo_relevance_brief.md")
        result["relevance_brief_json"] = str(paths.data_dir / "mini" / "current" / "ngo_relevance_brief.json")
        result["deep_evidence_json"] = str(paths.data_dir / "mini" / "current" / "deep_evidence.json")
    return result


def collect_live_and_build_pack(
    project_root: str | Path | None = None,
    profile_id: str = DEFAULT_PROFILE,
) -> dict[str, Any]:
    """Collect live public feeds, then rebuild the mini pack."""
    paths = project_paths(project_root)
    return {
        "collection": collect_live_sources(paths, profile_id),
        "pack": build_mini_pack(paths.project_root, profile_id),
    }


def build_relevance_brief(project_root: str | Path | None = None) -> dict[str, Any]:
    """Rebuild only the NGO/default-profile relevance brief."""
    paths = project_paths(project_root)
    counts = build_ngo_relevance_brief(paths)
    out_dir = paths.data_dir / "mini" / "current"
    return {
        "counts": counts,
        "relevance_brief_md": str(out_dir / "ngo_relevance_brief.md"),
        "relevance_brief_json": str(out_dir / "ngo_relevance_brief.json"),
        "deep_evidence_json": str(out_dir / "deep_evidence.json"),
    }


def build_pipeline_overview(project_root: str | Path | None = None) -> dict[str, Any]:
    """Return the same correlated overview shown by ``threatsucker overview``."""
    return build_overview(project_paths(project_root))


def import_local_evidence(
    project_root: str | Path | None = None,
    *,
    dnscap_path: str | Path | None = None,
    enumeros_json: str | Path | None = None,
    safesniff_json: str | Path | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    """Import collector outputs into local context.

    This is deliberately explicit so external software can pass stored JSON/CSV
    artifacts without invoking live collection tools on the same machine.
    """
    paths = project_paths(project_root)
    result: dict[str, Any] = {}
    if dnscap_path is not None:
        result["dnscap_highlights"] = len(highlight_current_mini(paths, Path(dnscap_path)))
    if enumeros_json is not None:
        result["enumeros_import"] = import_enumeros_json(paths, Path(enumeros_json), append=not replace)
        result["enumeros_findings"] = len(filter_enumeros_documents([Path(enumeros_json)], paths.data_dir / "mini" / "current"))
    if safesniff_json is not None:
        result["safesniff_import"] = import_safesniff_json(paths, Path(safesniff_json), append=not replace)
    return result
