import pytest

from ngo_intel.local_context.importers import CollectorJsonError, import_enumeros_json, import_safesniff_json, load_json_document
from ngo_intel.paths import ProjectPaths


def test_import_enumeros_json(tmp_path) -> None:
    paths = ProjectPaths(tmp_path)
    fixture = ProjectPaths.discover().project_root / "tests" / "fixtures" / "enumeros_sample.json"
    counts = import_enumeros_json(paths, fixture, append=False)
    assert counts["hosts"] == 1
    assert counts["browsers"] == 3
    assert counts["exposed_ports"] == 2
    assert (tmp_path / "local_context" / "assets" / "browsers.csv").exists()
    assert (tmp_path / "local_context" / "imported" / "enumeros" / "enumeros_sample.json").exists()


def test_import_safesniff_json(tmp_path) -> None:
    paths = ProjectPaths(tmp_path)
    fixture = ProjectPaths.discover().project_root / "tests" / "fixtures" / "safesniff_sample.json"
    counts = import_safesniff_json(paths, fixture, append=False)
    assert counts["hosts"] == 2
    assert counts["services"] == 1
    assert counts["exposed_ports"] == 1
    assert (tmp_path / "local_context" / "assets" / "exposed_ports.csv").exists()
    assert (tmp_path / "local_context" / "imported" / "safesniff" / "safesniff_sample.json").exists()


def test_load_json_document_reports_bad_json(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ nope", encoding="utf-8")

    with pytest.raises(CollectorJsonError, match="Invalid JSON"):
        load_json_document(bad)


def test_load_json_document_rejects_empty_and_non_object(tmp_path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")

    with pytest.raises(CollectorJsonError, match="empty"):
        load_json_document(empty)
    with pytest.raises(CollectorJsonError, match="Expected a JSON object"):
        load_json_document(array)
