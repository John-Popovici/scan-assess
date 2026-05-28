from datetime import datetime

from ngo_intel.models import NormalizedIndicator, OrgProfile


def test_models_validate() -> None:
    indicator = NormalizedIndicator(
        indicator_id="abc",
        source="misp_osint",
        type="domain",
        value="Example.org",
        normalized_value="example.org",
    )
    assert indicator.confidence == 50
    assert indicator.severity == "medium"

    profile = OrgProfile(
        org_name="Example Luxembourg NGO",
        country="LU",
        languages=["fr", "de", "en", "lb"],
        sector="charity",
        handles_sensitive_data=True,
        handles_donor_data=True,
        has_public_donation_page=True,
        uses_cloud_email=True,
        likely_targets=["phishing"],
        technical_capacity="low",
    )
    assert profile.country == "LU"
    assert isinstance(datetime.now(), datetime)
