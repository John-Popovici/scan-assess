from ngo_intel.overview import build_overview
from ngo_intel.paths import ProjectPaths


def test_overview_includes_safesniff_service_exposure() -> None:
    paths = ProjectPaths.discover()
    overview = build_overview(paths)

    assert "summary" in overview
    assert "devices" in overview
    assert "service_exposure" in overview
    assert any(item.get("source") == "safesniff" for item in overview["service_exposure"])


def test_overview_surfaces_enumeros_update_status() -> None:
    paths = ProjectPaths.discover()
    overview = build_overview(paths)

    assert "update_status" in overview
    assert overview["summary"]["outdated_assets"] >= 1
    assert any(item.get("subject") == "os" and item.get("status") == "outdated" for item in overview["update_status"])
