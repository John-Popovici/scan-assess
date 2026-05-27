from ngo_intel.mini import build_mini_items, load_mini_profile, run_mini
from ngo_intel.models import NormalizedIndicator
from ngo_intel.paths import ProjectPaths


def test_luxembourg_ngo_profile_filters_relevant_indicator() -> None:
    paths = ProjectPaths.discover()
    profile = load_mini_profile(paths, "luxembourg_ngo")
    indicator = NormalizedIndicator(
        indicator_id="demo",
        source="misp_osint",
        type="domain",
        value="invoice-bgl-secure.lu",
        normalized_value="invoice-bgl-secure.lu",
        threat_type=["phishing", "credential_theft"],
        description="Luxembourg invoice phishing using BGL BNP Paribas theme",
    )
    items = build_mini_items(profile, [indicator], [])
    assert len(items) == 1
    assert any("brand_term" in reason for reason in items[0]["include_reasons"])
    assert any("threat_focus" in reason for reason in items[0]["include_reasons"])


def test_run_mini_writes_context_pack() -> None:
    paths = ProjectPaths.discover()
    counts = run_mini(paths, "luxembourg_ngo")
    assert counts["included_items"] > 0
    assert (paths.data_dir / "mini" / "current" / "ai_context.md").exists()
    assert (paths.data_dir / "mini" / "current" / "threat_items.jsonl").exists()
