from pathlib import Path

from ngo_intel.local_context.enumeros_filter import filter_enumeros_documents


def test_filter_enumeros_windows_sample(tmp_path) -> None:
    fixture = Path("tests/fixtures/enumeros_windows_sample.json")
    findings = filter_enumeros_documents([fixture], tmp_path)
    kinds = {finding["kind"] for finding in findings}
    assert "outdated_software" in kinds
    assert "browser_detected" in kinds
    assert "open_port" in kinds
    assert any(finding["subject"] == "os" for finding in findings)
    assert any(finding["subject"] == "edge" for finding in findings)
    assert (tmp_path / "enumeros_findings.jsonl").exists()
