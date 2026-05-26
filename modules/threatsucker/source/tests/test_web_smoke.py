from ngo_intel.web import create_app


def test_web_dashboard_and_api_smoke(tmp_path) -> None:
    app = create_app(tmp_path)
    client = app.test_client()

    assert client.get("/").status_code == 200
    assert client.get("/brief").status_code == 200
    assert client.get("/api/outputs").status_code == 200
    assert client.get("/api/overview").status_code == 200
    assert client.get("/api/brief").status_code == 200
    assert client.get("/api/deep-evidence").status_code == 200
