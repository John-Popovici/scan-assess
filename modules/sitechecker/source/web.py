from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from flask import Flask, Response, flash, jsonify, redirect, render_template_string, request, url_for

from scanner import DEFAULT_CONFIG, DEFAULT_VERSION_POLICY, load_config, load_version_policy, run_validation_suite, scan_site, validate_config, validate_version_policy


MODULE_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = MODULE_ROOT / "config" / "scan_assess_runtime.json"
VERSION_POLICY_PATH = MODULE_ROOT / "config" / "version_policy.json"

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SiteChecker Controls</title>
  <style>
    :root { color-scheme: dark; --bg:#0f171b; --panel:#151d23; --ink:#eef4f2; --muted:#a9b7b3; --line:#2d3b42; --green:#2f8064; --red:#d16060; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
    main { max-width:1180px; margin:0 auto; padding:24px; }
    h1 { margin:0 0 4px; font-size:26px; }
    h2 { margin:0 0 12px; font-size:18px; }
    .muted { color:var(--muted); }
    .grid { display:grid; grid-template-columns:minmax(320px,.8fr) minmax(420px,1.2fr); gap:16px; align-items:start; }
    @media (max-width:900px) { .grid { grid-template-columns:1fr; } }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    label { display:block; color:var(--muted); font-weight:700; font-size:12px; margin:12px 0 4px; }
    input, textarea { width:100%; border:1px solid var(--line); border-radius:6px; background:#0d1418; color:var(--ink); padding:9px; }
    textarea { min-height:280px; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; line-height:1.45; }
    input[type=checkbox] { width:auto; }
    button, input[type=submit] { background:var(--green); color:white; border:0; border-radius:6px; padding:9px 12px; font-weight:800; cursor:pointer; }
    .secondary { background:transparent; border:1px solid var(--green); color:#9ad7c1; }
    .danger { color:#ffb0b0; }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
    .pill { display:inline-flex; border:1px solid var(--line); border-radius:999px; padding:4px 9px; color:var(--muted); }
    .ok { color:#9de0c4; border-color:#3d8069; }
    .bad { color:#ffaaaa; border-color:#974747; }
    pre { overflow:auto; max-height:620px; background:#081013; padding:14px; border-radius:8px; border:1px solid var(--line); }
    .flash { border:1px solid #6b6236; background:#292616; padding:10px; border-radius:8px; margin:12px 0; }
    table { width:100%; border-collapse:collapse; }
    td, th { border-bottom:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }
  </style>
</head>
<body><main>
  <h1>SiteChecker</h1>
  <div class="muted">Owner-authorized website exposure and hardening checks.</div>
  {% with messages = get_flashed_messages() %}
    {% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}
  {% endwith %}
  {{ body|safe }}
</main></body>
</html>
"""

INDEX = """
<section class="grid">
  <form class="panel" method="post" action="{{ url_for('save_config') }}">
    <h2>Configuration</h2>
    <label><input type="checkbox" name="enabled" {% if config.enabled %}checked{% endif %}> Enabled for scan-assess runs</label>
    <label>Website URL</label>
    <input name="target_url" value="{{ config.target_url }}" placeholder="https://example.org">
    <label>Max internal pages</label>
    <input name="max_pages" value="{{ config.max_pages }}">
    <label>Crawl delay seconds</label>
    <input name="crawl_delay_seconds" value="{{ config.crawl_delay_seconds }}">
    <label>Request timeout seconds</label>
    <input name="request_timeout_seconds" value="{{ config.request_timeout_seconds }}">
    <h2 style="margin-top:18px">Checks</h2>
    <label><input type="checkbox" name="check_security_headers" {% if config.check_security_headers %}checked{% endif %}> Security headers</label>
    <label><input type="checkbox" name="check_cookie_flags" {% if config.check_cookie_flags %}checked{% endif %}> Cookie flags</label>
    <label><input type="checkbox" name="crawl_same_site" {% if config.crawl_same_site %}checked{% endif %}> Crawl same-site pages</label>
    <label><input type="checkbox" name="check_interesting_paths" {% if config.check_interesting_paths %}checked{% endif %}> Check common exposure paths</label>
    <label><input type="checkbox" name="check_versions" {% if config.check_versions %}checked{% endif %}> Version heuristics</label>
    <label>Version policy JSON</label>
    <textarea name="version_policy">{{ version_policy_json }}</textarea>
    <div class="actions">
      <input type="submit" value="Save config">
      <button class="secondary" formaction="{{ url_for('run_check') }}" formmethod="post">Run check now</button>
      <button class="secondary" formaction="{{ url_for('run_validation') }}" formmethod="post">Run validation</button>
    </div>
  </form>
  <div class="panel">
    <h2>Status</h2>
    <p><span class="pill {{ 'ok' if validation.valid else 'bad' }}">{{ validation.summary }}</span></p>
    {% if validation.messages %}
      <ul class="danger">{% for message in validation.messages %}<li>{{ message }}</li>{% endfor %}</ul>
    {% endif %}
    {% if validation.warnings %}
      <ul class="muted">{% for warning in validation.warnings %}<li>{{ warning }}</li>{% endfor %}</ul>
    {% endif %}
    <p><span class="pill {{ 'ok' if version_validation.valid else 'bad' }}">Version policy: {{ 'valid' if version_validation.valid else 'invalid' }}</span></p>
    {% if version_validation.messages %}
      <ul class="danger">{% for message in version_validation.messages %}<li>{{ message }}</li>{% endfor %}</ul>
    {% endif %}
    <table>
      <tr><td>Target</td><td>{{ config.target_url }}</td></tr>
      <tr><td>Scope</td><td>Single owner-authorized website only</td></tr>
      <tr><td>Checks</td><td>
        <ul>
          {% if config.check_security_headers %}<li>Security response headers</li>{% endif %}
          {% if config.check_cookie_flags %}<li>Cookie Secure, HttpOnly, and SameSite flags</li>{% endif %}
          {% if config.crawl_same_site %}<li>Same-site crawl for login/forms/email/technology markers</li>{% endif %}
          {% if config.check_interesting_paths %}<li>Common exposure paths such as security.txt, robots.txt, .env, .git, phpinfo, server-status, and WordPress admin/login</li>{% endif %}
          {% if config.check_versions %}<li>Version heuristics for legacy frontend/CMS components</li>{% endif %}
        </ul>
      </td></tr>
      <tr><td>Version baseline</td><td>Detected versions are compared against editable minimum-supported versions first, then broader stale-major rules.</td></tr>
      <tr><td>Output</td><td><code>outputs/&lt;run&gt;/sitechecker/sitechecker.json</code></td></tr>
    </table>
  </div>
</section>
{% if result %}
  <section class="panel" style="margin-top:16px">
    <h2>{{ result_title }}</h2>
    <pre>{{ result_json }}</pre>
  </section>
{% endif %}
"""


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = "sitechecker-local-dev"

    @app.get("/")
    def index() -> str:
        return render_page()

    @app.post("/config/save")
    def save_config() -> Response:
        config = _form_config()
        version_policy, policy_error = _form_version_policy()
        if policy_error:
            flash("Version policy not saved: " + policy_error)
            return render_page(config=config, version_policy=DEFAULT_VERSION_POLICY)
        config["version_policy"] = version_policy
        validation = validate_config(config)
        if not validation["valid"]:
            flash("Config not saved: " + "; ".join(validation["messages"]))
            return render_page(config=config, version_policy=version_policy)
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        runtime_config = {key: value for key, value in config.items() if key != "version_policy"}
        CONFIG_PATH.write_text(json.dumps(runtime_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        VERSION_POLICY_PATH.write_text(json.dumps(version_policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        flash("Saved SiteChecker config.")
        return redirect(url_for("index"))

    @app.post("/check")
    def run_check() -> str:
        config = _form_config()
        version_policy, policy_error = _form_version_policy()
        if policy_error:
            result = {"status": "invalid_version_policy", "error": policy_error}
            return render_page(config=config, version_policy=DEFAULT_VERSION_POLICY, result=result, result_title="Check result")
        config["version_policy"] = version_policy
        validation = validate_config(config)
        if validation["valid"]:
            result = scan_site(config)
        else:
            result = {"status": "invalid_config", "validation": validation}
        return render_page(config=config, result=result, result_title="Check result")

    @app.post("/validation")
    def run_validation() -> str:
        result = run_validation_suite()
        flash("Validation suite passed." if result["status"] == "pass" else "Validation suite has failures.")
        return render_page(result=result, result_title="Validation result")

    @app.get("/api/config")
    def api_config() -> Any:
        config = load_config(CONFIG_PATH)
        return jsonify({"config": config, "validation": validate_config(config), "version_policy": config.get("version_policy", DEFAULT_VERSION_POLICY)})

    @app.get("/api/validation")
    def api_validation() -> Any:
        return jsonify(run_validation_suite())

    return app


def render_page(
    config: dict[str, Any] | None = None,
    version_policy: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    result_title: str = "",
) -> str:
    config = config or load_config(CONFIG_PATH)
    version_policy = version_policy or config.get("version_policy") or load_version_policy(VERSION_POLICY_PATH)
    config["version_policy"] = version_policy
    body = render_template_string(
        INDEX,
        config=_obj(config),
        validation=_obj(validate_config(config)),
        version_validation=_obj(validate_version_policy(version_policy)),
        version_policy_json=json.dumps(version_policy, indent=2, sort_keys=True),
        result=result,
        result_title=result_title,
        result_json=json.dumps(result, indent=2, sort_keys=True) if result else "",
    )
    return render_template_string(PAGE, body=body)


def _form_config() -> dict[str, Any]:
    return {
        "enabled": request.form.get("enabled") == "on",
        "target_url": request.form.get("target_url", "").strip(),
        "max_pages": _int(request.form.get("max_pages"), DEFAULT_CONFIG["max_pages"]),
        "crawl_delay_seconds": _float(request.form.get("crawl_delay_seconds"), DEFAULT_CONFIG["crawl_delay_seconds"]),
        "request_timeout_seconds": _int(request.form.get("request_timeout_seconds"), DEFAULT_CONFIG["request_timeout_seconds"]),
        "check_security_headers": request.form.get("check_security_headers") == "on",
        "check_cookie_flags": request.form.get("check_cookie_flags") == "on",
        "crawl_same_site": request.form.get("crawl_same_site") == "on",
        "check_interesting_paths": request.form.get("check_interesting_paths") == "on",
        "check_versions": request.form.get("check_versions") == "on",
    }


def _form_version_policy() -> tuple[dict[str, Any], str | None]:
    raw = request.form.get("version_policy", "").strip()
    if not raw:
        return json.loads(json.dumps(DEFAULT_VERSION_POLICY)), None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {}, f"JSON parse error at line {exc.lineno}, column {exc.colno}: {exc.msg}"
    if not isinstance(parsed, dict):
        return {}, "Version policy must be a JSON object."
    validation = validate_version_policy(parsed)
    if not validation["valid"]:
        return parsed, "; ".join(validation["messages"])
    return parsed, None


def _int(value: str | None, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _float(value: str | None, default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


class _obj(dict):
    def __getattr__(self, key: str) -> Any:
        return self.get(key)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8775)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
