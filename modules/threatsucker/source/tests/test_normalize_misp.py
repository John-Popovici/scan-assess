import json
from pathlib import Path

from ngo_intel.sources.misp_feed import normalize_misp_event


def test_misp_fixture_produces_expected_indicators() -> None:
    fixture = Path("tests/fixtures/misp_event_sample.json")
    indicators = normalize_misp_event(json.loads(fixture.read_text()), str(fixture))
    values = {item.normalized_value for item in indicators}
    assert "login-example-ngo-support.lu" in values
    assert "203.0.113.44" in values
    assert any(item.type == "cve" for item in indicators)
    phishing = next(item for item in indicators if item.normalized_value == "login-example-ngo-support.lu")
    assert "phishing" in phishing.threat_type
