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
    assert client.get("/validation").status_code == 200


def test_web_validation_suite(tmp_path) -> None:
    app = create_app(tmp_path)
    client = app.test_client()

    response = client.post("/validation/run", follow_redirects=True)

    assert response.status_code == 200
    result = client.get("/api/validation").get_json()
    assert result["status"] == "pass"
    assert result["summary"]["total"] == 3
    assert result["summary"]["failed"] == 0
