from ngo_intel.config import load_scoring_rules
from ngo_intel.local_context.loader import load_local_context
from ngo_intel.models import LocalContext
from ngo_intel.models import NormalizedIndicator
from ngo_intel.paths import ProjectPaths
from ngo_intel.scoring import score_indicator


def _rules() -> dict:
    return load_scoring_rules("config/scoring_rules.yaml")


def _context():
    return load_local_context(ProjectPaths.discover())


def _context_with_dns(domain: str) -> LocalContext:
    context = _context()
    data = context.model_dump()
    data["dns_queries"] = [
        *data["dns_queries"],
        {"timestamp": "2026-05-02T10:00:00Z", "host": "test-host", "queried_domain": domain, "query_type": "A"},
    ]
    return LocalContext.model_validate(data)


def test_dns_matched_phishing_domain_scores_high() -> None:
    indicator = NormalizedIndicator(
        indicator_id="i1",
        source="misp_osint",
        type="domain",
        value="login-example-ngo-support.lu",
        normalized_value="login-example-ngo-support.lu",
        threat_type=["phishing", "credential_theft"],
        tags=["Luxembourg"],
        confidence=80,
    )
    scored = score_indicator(indicator, _context_with_dns("login-example-ngo-support.lu"), _rules())
    assert scored.score >= 70
    assert scored.priority in {"high", "critical"}
    assert any("matched_dns_query" in reason for reason in scored.reasons)


def test_allowlisted_domain_scores_archive_or_low() -> None:
    indicator = NormalizedIndicator(
        indicator_id="i2",
        source="phishtank_verified",
        type="domain",
        value="microsoft.com",
        normalized_value="microsoft.com",
        threat_type=["phishing"],
    )
    scored = score_indicator(indicator, _context(), _rules())
    assert scored.priority in {"archive", "low"}
    assert any("allowlisted_domain" in reason for reason in scored.reasons)


def test_no_local_match_generic_indicator_is_penalized() -> None:
    indicator = NormalizedIndicator(
        indicator_id="i3",
        source="misp_osint",
        type="domain",
        value="random-global-noise.example",
        normalized_value="random-global-noise.example",
        threat_type=[],
    )
    scored = score_indicator(indicator, _context(), _rules())
    assert scored.score <= 25
    assert any("no_local_match" in reason for reason in scored.reasons)
