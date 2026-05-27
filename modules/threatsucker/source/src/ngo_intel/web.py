from __future__ import annotations

import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

try:
    from flask import Flask, Response, flash, jsonify, redirect, render_template_string, request, url_for
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only with incomplete installs
    raise ModuleNotFoundError("Flask is required for the web interface. Install with: pip install -e .") from exc

from .io_utils import read_jsonl
from .config_sets import (
    CONFIG_FILES,
    active_config_set_name,
    apply_config_set,
    ensure_default_config_set,
    list_config_sets,
    read_config_file,
    save_active_as_config_set,
    write_config_file,
)
from .live_collect import collect_live_sources
from .local_context.dnscap_highlight import highlight_current_mini
from .local_context.enumeros_filter import filter_enumeros_documents
from .local_context.importers import CollectorJsonError, import_enumeros_json, import_safesniff_json
from .mini import list_mini_profiles, run_mini
from .normalize import normalize_all
from .ngo_brief import build_ngo_relevance_brief
from .overview import build_overview
from .paths import ProjectPaths
from .scoring import score_all


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ThreatSucker</title>
  <style>
    :root {
      color-scheme: light;
      --bg:#f5f7fa; --panel:#ffffff; --ink:#17202c; --muted:#5d6978;
      --line:#d9e0ea; --blue:#21598f; --green:#217a55; --amber:#94611a;
      --red:#a33b3b; --soft-blue:#eaf2fb; --soft-green:#e9f7f0; --soft-amber:#fff4df;
    }
    * { box-sizing:border-box; }
    body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg); color:var(--ink); }
    header { background:#172538; color:white; padding:22px 32px; }
    main { max-width:1240px; margin:0 auto; padding:22px 24px 40px; }
    h1 { margin:0; font-size:25px; line-height:1.1; }
    h2 { margin:0 0 12px; font-size:17px; }
    h3 { margin:0 0 6px; font-size:14px; color:var(--muted); font-weight:650; }
    a { color:#174f84; text-decoration-thickness:1px; text-underline-offset:2px; }
    .topbar { display:flex; justify-content:space-between; gap:20px; align-items:flex-end; }
    .subtitle { color:#d7e2ef; margin-top:4px; }
    .quicklinks { display:flex; gap:12px; flex-wrap:wrap; font-size:14px; }
    .quicklinks a { color:#dcecff; }
    .grid { display:grid; grid-template-columns:repeat(12, 1fr); gap:16px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; box-shadow:0 1px 2px rgba(18,32,50,.04); }
    .span-4 { grid-column:span 4; } .span-5 { grid-column:span 5; } .span-6 { grid-column:span 6; } .span-7 { grid-column:span 7; } .span-8 { grid-column:span 8; } .span-12 { grid-column:span 12; }
    @media (max-width: 900px) { .span-4,.span-5,.span-6,.span-7,.span-8 { grid-column:span 12; } .topbar { align-items:flex-start; flex-direction:column; } }
    .muted { color:var(--muted); }
    .pill { display:inline-flex; align-items:center; gap:6px; padding:4px 9px; border-radius:999px; font-size:12px; border:1px solid var(--line); background:#f8fafc; }
    .ok { background:var(--soft-green); color:var(--green); border-color:#b9dec9; }
    .missing { background:var(--soft-amber); color:#744600; border-color:#ead29b; }
    .warn { background:#fff0ee; color:var(--red); border-color:#ecc0ba; }
    .statgrid { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:12px; margin:18px 0; }
    @media (max-width: 900px) { .statgrid { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
    .stat { background:white; border:1px solid var(--line); border-radius:8px; padding:13px 14px; }
    .stat strong { display:block; font-size:26px; line-height:1; margin-bottom:5px; }
    .stat span { color:var(--muted); font-size:13px; }
    .actions { display:flex; gap:10px; flex-wrap:wrap; align-items:end; }
    button, input[type=submit] { background:var(--blue); color:white; border:0; border-radius:6px; padding:8px 12px; cursor:pointer; font-weight:650; }
    .secondary { background:#eef3f8; color:#16324f; border:1px solid var(--line); }
    input[type=text], select, textarea { width:100%; border:1px solid var(--line); border-radius:6px; padding:8px; background:white; }
    textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; min-height:140px; resize:vertical; line-height:1.4; }
    label { display:block; color:var(--muted); font-size:12px; font-weight:650; margin-bottom:4px; }
    form { margin:0; }
    .formline { display:grid; grid-template-columns:180px 1fr auto; gap:10px; align-items:end; }
    @media (max-width: 800px) { .formline { grid-template-columns:1fr; } }
    pre { white-space:pre-wrap; background:#0d1520; color:#eef4ff; padding:14px; border-radius:8px; overflow:auto; max-height:520px; }
    table { width:100%; border-collapse:collapse; }
    th, td { text-align:left; padding:9px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
    .compact td { padding:7px 6px; }
    .flash { background:#fff8d8; border:1px solid #eadb8f; padding:10px 12px; border-radius:8px; margin-bottom:14px; }
    .hint { border-left:4px solid var(--amber); padding-left:10px; margin-bottom:10px; }
    .paths { font-size:12px; color:var(--muted); word-break:break-all; }
    .rule-layout { display:grid; grid-template-columns:minmax(380px, 1.05fr) minmax(420px, .95fr); gap:16px; align-items:start; }
    @media (max-width: 1000px) { .rule-layout { grid-template-columns:1fr; } }
    .rule-toolbar { display:flex; justify-content:space-between; gap:12px; align-items:center; margin-bottom:12px; }
    .rule-groups { display:grid; gap:14px; }
    .rule-group { border-top:1px solid var(--line); padding-top:12px; }
    .rule-group:first-child { border-top:0; padding-top:0; }
    .rule-row { display:grid; grid-template-columns:minmax(170px, 240px) 1fr 52px; gap:12px; align-items:center; padding:8px 0; }
    .rule-name { font-size:13px; font-weight:650; overflow-wrap:anywhere; }
    .rule-value { font-variant-numeric:tabular-nums; text-align:right; font-weight:700; }
    input[type=range] { width:100%; accent-color:var(--blue); }
    .meter { height:10px; background:#eef2f6; border-radius:999px; overflow:hidden; border:1px solid #dce3ec; }
    .meter span { display:block; height:100%; background:linear-gradient(90deg, #2f7d63, #d69a2d, #b95050); }
    .validation-box { border:1px solid var(--line); border-radius:8px; padding:12px; background:#f8fafc; }
    .validation-list { margin:8px 0 0; padding-left:18px; color:var(--red); }
    .yaml-editor { min-height:520px; }
    .file-validation { margin-top:8px; font-size:13px; }
    .source-grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:12px; }
    @media (max-width: 900px) { .source-grid { grid-template-columns:1fr; } }
    .source-card { border:1px solid var(--line); border-radius:8px; padding:13px; background:#fbfcfe; }
    .source-card header { background:transparent; color:var(--ink); padding:0; display:flex; justify-content:space-between; align-items:center; gap:10px; }
    .source-card h3 { margin:0; color:var(--ink); font-size:15px; }
    .switch { display:inline-flex; align-items:center; gap:8px; font-size:13px; font-weight:700; color:var(--muted); }
    .switch input { width:38px; height:20px; accent-color:var(--blue); }
    .source-fields { display:grid; grid-template-columns:1fr 110px; gap:10px; margin-top:12px; }
    @media (max-width: 700px) { .source-fields { grid-template-columns:1fr; } }
    .source-path { margin-top:10px; }
    .source-counts { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
    .operator-bar { display:grid; grid-template-columns:minmax(280px, 1fr) auto; gap:16px; align-items:end; background:white; border:1px solid var(--line); border-radius:8px; padding:16px; }
    @media (max-width: 900px) { .operator-bar { grid-template-columns:1fr; } }
    .config-picker { display:grid; grid-template-columns:220px 1fr auto; gap:10px; align-items:end; }
    @media (max-width: 800px) { .config-picker { grid-template-columns:1fr; } }
    .operator-actions { display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end; }
    .operator-shell { display:grid; grid-template-columns:220px 1fr; gap:22px; margin-top:18px; align-items:start; }
    @media (max-width: 1000px) { .operator-shell { grid-template-columns:1fr; } }
    .operator-rail { position:sticky; top:14px; display:grid; gap:8px; }
    @media (max-width: 1000px) { .operator-rail { position:static; grid-template-columns:repeat(4, minmax(0, 1fr)); } }
    @media (max-width: 700px) { .operator-rail { grid-template-columns:1fr 1fr; } }
    .rail-link { display:block; padding:11px 12px; border:1px solid var(--line); border-radius:8px; background:white; color:var(--ink); font-weight:700; text-decoration:none; }
    .rail-link.active { border-color:#9fbfe2; background:#edf5ff; color:#123d68; }
    .rail-status { background:white; border:1px solid var(--line); border-radius:8px; padding:12px; }
    .workspace { display:grid; gap:22px; }
    .workspace-section { scroll-margin-top:18px; }
    .section-head { display:flex; justify-content:space-between; align-items:end; gap:14px; margin-bottom:12px; }
    .section-head h2 { margin:0; font-size:22px; }
    .section-kpis { display:flex; gap:8px; flex-wrap:wrap; }
    .quiet-panel { background:white; border:1px solid var(--line); border-radius:8px; padding:16px; }
    .yaml-drawer { background:white; border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .yaml-drawer summary { cursor:pointer; padding:14px 16px; font-weight:800; }
    .yaml-drawer .drawer-body { padding:0 16px 16px; display:grid; gap:14px; }
    .raw-file { border-top:1px solid var(--line); padding-top:14px; }
    .raw-file:first-child { border-top:0; }
    .raw-file h3 { color:var(--ink); font-size:14px; margin-bottom:8px; }
    .compact-yaml { min-height:220px; max-height:360px; }
    .validation-strip { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .import-row { display:grid; grid-template-columns:220px 1fr auto; gap:10px; align-items:end; }
    @media (max-width: 800px) { .import-row { grid-template-columns:1fr; } }
    .validation-grid { display:grid; grid-template-columns:minmax(320px, .85fr) minmax(420px, 1.15fr); gap:16px; align-items:start; }
    @media (max-width: 1000px) { .validation-grid { grid-template-columns:1fr; } }
    .case-list { display:grid; gap:10px; }
    .case-card { border:1px solid var(--line); border-radius:8px; padding:13px; background:white; }
    .case-card.pass { border-color:#b9dec9; background:#f7fcf9; }
    .case-card.fail { border-color:#ecc0ba; background:#fff8f7; }
    .case-title { display:flex; justify-content:space-between; gap:10px; align-items:start; margin-bottom:8px; }
    .case-title strong { font-size:15px; }
    .result-kpis { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:10px; margin:12px 0; }
    @media (max-width: 900px) { .result-kpis { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
    .result-kpi { border:1px solid var(--line); border-radius:8px; padding:10px; background:#fbfcfe; }
    .result-kpi strong { display:block; font-size:22px; }
    .validation-json { max-height:520px; font-size:12px; }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>ThreatSucker</h1>
        <div class="subtitle">Local evidence and threat context for AI-assisted review</div>
      </div>
      <nav class="quicklinks">
        <a href="{{ url_for('brief_md') }}">Human brief</a>
        <a href="{{ url_for('config_page') }}">Config</a>
        <a href="{{ url_for('validation_page') }}">Validation</a>
        <a href="{{ url_for('api_overview') }}">Overview JSON</a>
        <a href="{{ url_for('api_brief') }}">Brief JSON</a>
        <a href="{{ url_for('api_deep_evidence') }}">Deep evidence</a>
      </nav>
    </div>
  </header>
  <main>
    {% with messages = get_flashed_messages() %}
      {% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}
    {% endwith %}
    {{ body|safe }}
  </main>
</body>
</html>
"""


def create_app(project_root: str | Path | None = None) -> Flask:
    paths = ProjectPaths.discover(project_root)
    ensure_default_config_set(paths)
    app = Flask(__name__)
    app.secret_key = "threatsucker-local-dev"

    @app.get("/")
    def index() -> str:
        mini_dir = paths.data_dir / "mini" / "current"
        brief = _read_json(mini_dir / "ngo_relevance_brief.json")
        deep = _read_json(mini_dir / "deep_evidence.json")
        overview = build_overview(paths)
        body = render_template_string(
            DASHBOARD,
            paths=paths,
            profiles=list_mini_profiles(paths),
            outputs=_output_status(mini_dir),
            collectors=_collector_status(paths),
            brief=brief,
            deep=deep,
            overview=overview,
        )
        return render_template_string(PAGE, body=body)

    @app.post("/actions/mini")
    def action_mini() -> Response:
        profile = request.form.get("profile") or "luxembourg_ngo"
        counts = run_mini(paths, profile)
        flash(f"Mini pack rebuilt for {profile}: {counts['included_items']} included items.")
        return redirect(url_for("index"))

    @app.post("/actions/brief")
    def action_brief() -> Response:
        counts = build_ngo_relevance_brief(paths)
        flash(f"Relevance brief rebuilt: {counts['brief_items']} report items.")
        return redirect(url_for("index"))

    @app.post("/actions/collect-live")
    def action_collect_live() -> Response:
        profile = request.form.get("profile") or "luxembourg_ngo"
        summary = collect_live_sources(paths, profile)
        counts = run_mini(paths, profile)
        build_ngo_relevance_brief(paths)
        flash(f"Live collection complete: {len(summary['sources'])} sources checked, {counts['included_items']} mini items.")
        return redirect(url_for("index"))

    @app.post("/actions/import")
    def action_import() -> Response:
        kind = request.form.get("kind", "")
        source_path = Path(request.form.get("path", "")).expanduser()
        if not source_path.exists():
            flash(f"Input path does not exist: {source_path}")
            return redirect(url_for("index"))
        try:
            if kind == "dnscap":
                count = len(highlight_current_mini(paths, source_path))
                flash(f"DNScap highlighted {count} local DNS match(es).")
            elif kind == "enumeros":
                counts = import_enumeros_json(paths, source_path)
                findings = filter_enumeros_documents([source_path], paths.data_dir / "mini" / "current")
                flash(f"Enumeros imported: {counts}; findings={len(findings)}.")
            elif kind == "safesniff":
                counts = import_safesniff_json(paths, source_path)
                flash(f"SafeSniff imported: {counts}.")
            else:
                flash("Unknown import type.")
        except CollectorJsonError as exc:
            flash(str(exc))
        return redirect(url_for("index"))

    @app.get("/config")
    def config_page() -> str:
        selected = request.args.get("set") or active_config_set_name(paths)
        names = {item.name for item in list_config_sets(paths)}
        if selected not in names:
            selected = "default"
        files = _config_editor_files(paths, selected)
        scoring_file = next((item for item in files if item["path"] == "config/scoring_rules.yaml"), None)
        source_file = next((item for item in files if item["path"] == "config/source_config.yaml"), None)
        other_files = [item for item in files if item["path"] != "config/scoring_rules.yaml"]
        scoring_visual = _scoring_visual(scoring_file["text"] if scoring_file else "")
        source_visual = _source_visual(source_file["text"] if source_file else "", paths)
        validation = _validate_config_payload({item["path"]: item["text"] for item in files})
        body = render_template_string(
            CONFIG_EDITOR,
            config_sets=list_config_sets(paths),
            selected=selected,
            scoring_file=scoring_file,
            scoring_visual=scoring_visual,
            source_visual=source_visual,
            other_files=other_files,
            validation=validation,
        )
        return render_template_string(PAGE, body=body)

    @app.post("/config/save")
    def config_save() -> Response:
        selected = request.form.get("config_set") or "default"
        try:
            _save_config_form(paths, selected)
            flash(f"Saved config set: {selected}")
        except (OSError, ValueError, yaml.YAMLError) as exc:
            flash(f"Could not save config set: {exc}")
        return redirect(url_for("config_page", set=selected))

    @app.post("/config/apply")
    def config_apply() -> Response:
        selected = request.form.get("config_set") or "default"
        try:
            if any(key.startswith("file:") for key in request.form):
                _save_config_form(paths, selected)
            item = apply_config_set(paths, selected)
            flash(f"Applied config set: {item.name}")
        except (OSError, ValueError, yaml.YAMLError) as exc:
            flash(f"Could not apply config set: {exc}")
        return redirect(url_for("config_page", set=selected))

    @app.post("/config/validate")
    def config_validate() -> Any:
        payload = request.get_json(silent=True) or {}
        files = payload.get("files", {})
        if not isinstance(files, dict):
            return jsonify({"valid": False, "files": {}, "errors": ["Expected files object."]}), 400
        validation = _validate_config_payload({str(key): str(value) for key, value in files.items()})
        scoring_text = str(files.get("config/scoring_rules.yaml", ""))
        return jsonify(
            {
                "valid": validation["valid"],
                "files": validation["files"],
                "messages": validation["messages"],
                "summary": validation["summary"],
                "scoring_visual": _scoring_visual(scoring_text),
                "source_visual": _source_visual(str(files.get("config/source_config.yaml", "")), paths),
            }
        )

    @app.post("/config/create")
    def config_create() -> Response:
        name = request.form.get("name") or ""
        try:
            item = save_active_as_config_set(paths, name, overwrite=False)
            flash(f"Created config set: {item.name}")
            return redirect(url_for("config_page", set=item.name))
        except (OSError, ValueError) as exc:
            flash(f"Could not create config set: {exc}")
            return redirect(url_for("config_page"))

    @app.post("/config/import-source")
    def config_import_source() -> Response:
        selected = request.form.get("config_set") or active_config_set_name(paths)
        source = request.form.get("source") or ""
        source_path = Path(request.form.get("path", "")).expanduser()
        try:
            copied = _import_source_files(paths, source, source_path)
            flash(f"Imported {copied} file(s) for {source}.")
        except (OSError, ValueError) as exc:
            flash(f"Could not import source files: {exc}")
        return redirect(url_for("config_page", set=selected))

    @app.get("/validation")
    def validation_page() -> str:
        results = _read_json(paths.data_dir / "validation_runs" / "current" / "validation_result.json")
        body = render_template_string(VALIDATION_PAGE, results=results)
        return render_template_string(PAGE, body=body)

    @app.post("/validation/run")
    def validation_run() -> Response:
        try:
            results = _run_validation_suite(paths)
            failed = [case for case in results["cases"] if not case["passed"]]
            flash(
                "Validation suite passed."
                if not failed
                else f"Validation suite completed with {len(failed)} failing case(s)."
            )
        except Exception as exc:
            flash(f"Validation suite failed to run: {exc}")
        return redirect(url_for("validation_page"))

    @app.get("/api/validation")
    def api_validation() -> Any:
        result_path = paths.data_dir / "validation_runs" / "current" / "validation_result.json"
        if not result_path.exists():
            return jsonify({"status": "not_run", "cases": []})
        return jsonify(_read_json(result_path))

    @app.get("/brief")
    def brief_md() -> str:
        path = paths.data_dir / "mini" / "current" / "ngo_relevance_brief.md"
        text = path.read_text(encoding="utf-8") if path.exists() else "No brief has been generated yet."
        body = f"<p><a href='{url_for('index')}'>Back</a></p><pre>{_escape(text)}</pre>"
        return render_template_string(PAGE, body=body)

    @app.get("/api/brief")
    def api_brief() -> Any:
        return jsonify(_read_json(paths.data_dir / "mini" / "current" / "ngo_relevance_brief.json"))

    @app.get("/api/deep-evidence")
    def api_deep_evidence() -> Any:
        return jsonify(_read_json(paths.data_dir / "mini" / "current" / "deep_evidence.json"))

    @app.get("/api/outputs")
    def api_outputs() -> Any:
        mini_dir = paths.data_dir / "mini" / "current"
        return jsonify({"outputs": _output_status(mini_dir), "collectors": _collector_status(paths)})

    @app.get("/api/overview")
    def api_overview() -> Any:
        return jsonify(build_overview(paths))

    return app


DASHBOARD = """
<section class="statgrid">
  <div class="stat"><strong>{{ overview.summary.devices }}</strong><span>devices known</span></div>
  <div class="stat"><strong>{{ overview.summary.outdated_assets }}</strong><span>outdated OS/software</span></div>
  <div class="stat"><strong>{{ overview.summary.safesniff_high_exposures }}</strong><span>SafeSniff high exposures</span></div>
  <div class="stat"><strong>{{ overview.summary.local_dns_threat_matches }}</strong><span>local DNS threat matches</span></div>
</section>

<section class="grid">
  <div class="panel span-7">
    <h2>Attention</h2>
    {% for hint in overview.correlation_hints %}
      <div class="hint">
        <h3>{{ hint.kind.replace('_', ' ') }}</h3>
        <div>{{ hint.summary }}</div>
      </div>
    {% endfor %}
  </div>
  <div class="panel span-5">
    <h2>Evidence Pack</h2>
    <table class="compact">
      <tr><td>Brief items</td><td>{{ brief.get('boundaries', {}).get('brief_items_retained', 0) }}</td></tr>
      <tr><td>Deep evidence records</td><td>{{ deep.get('record_count', 0) }}</td></tr>
      <tr><td>Profile</td><td>{{ profiles[0].profile_id if profiles else 'none' }}</td></tr>
      <tr><td>Demo threat items hidden</td><td>{{ overview.summary.demo_threat_items_hidden }}</td></tr>
      <tr><td>Demo vulnerabilities hidden</td><td>{{ overview.summary.demo_vulnerabilities_hidden }}</td></tr>
    </table>
    <p class="muted">The compact report references deep evidence IDs for drill-down.</p>
    <p class="muted">Live public sources are used when collected. PhishTank live use may require a configured key/feed; fixture data is hidden from this overview.</p>
  </div>
</section>

<section class="panel" style="margin-top:16px">
  <h2>Actions</h2>
  <div class="actions">
    <form method="post" action="{{ url_for('action_mini') }}">
      <input type="hidden" name="profile" value="luxembourg_ngo">
      <input type="submit" value="Build mini pack">
    </form>
    <form method="post" action="{{ url_for('action_brief') }}">
      <input type="submit" value="Build relevance brief">
    </form>
    <form method="post" action="{{ url_for('action_collect_live') }}">
      <input type="submit" value="Collect live feeds and rebuild">
    </form>
  </div>
  <p class="muted">CLI remains the main interface. This page is an operator overview of the same files and commands.</p>
</section>

<section class="grid" style="margin-top:16px">
  <div class="panel span-8">
    <h2>Devices And Local Context</h2>
    <table>
      <thead><tr><th>Device</th><th>OS</th><th>Software</th><th>Browsers</th><th>Outdated</th><th>High-risk services</th><th>DNS hits</th></tr></thead>
      <tbody>
      {% for device in overview.devices[:8] %}
        <tr>
          <td>{{ device.host }}</td>
          <td>{{ ', '.join(device.os) if device.os else '-' }}</td>
          <td>{{ device.software_count }}</td>
          <td>{{ device.browser_count }}</td>
          <td>
            {% if device.outdated_count %}
              <span class="pill warn">{{ device.outdated_count }}</span>
            {% else %}0{% endif %}
          </td>
          <td>
            {% if device.high_risk_services %}
              {% for svc in device.high_risk_services[:3] %}
                <span class="pill warn">{{ svc.service }}:{{ svc.port }}</span>
              {% endfor %}
            {% else %}-{% endif %}
          </td>
          <td>{{ device.threat_dns_matches|length }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="panel span-4">
    <h2>Collectors</h2>
    <table class="compact">
      {% for item in collectors.tools %}
      <tr><td>{{ item.name }}</td><td><span class="pill {{ 'ok' if item.available else 'missing' }}">{{ 'installed' if item.available else 'optional' }}</span></td></tr>
      {% endfor %}
    </table>
    <p class="muted">Stored outputs work even if the tools are not installed here.</p>
  </div>
</section>

<section class="grid" style="margin-top:16px">
  <div class="panel span-5">
    <h2>Enumeros Update Status</h2>
    <table>
      <thead><tr><th>Host</th><th>Item</th><th>Status</th><th>Installed</th><th>Latest</th></tr></thead>
      <tbody>
      {% if not overview.update_status %}
        <tr><td colspan="5" class="muted">No Enumeros version-status findings have been imported or filtered yet.</td></tr>
      {% endif %}
      {% for row in overview.update_status[:8] %}
        <tr>
          <td>{{ row.host }}</td>
          <td>{{ row.subject }}</td>
          <td><span class="pill {{ 'warn' if row.status == 'outdated' else 'missing' }}">{{ row.status }}</span></td>
          <td>{{ row.installed or '-' }}</td>
          <td>{{ row.latest or '-' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="panel span-7">
    <h2>Threat Context By Source</h2>
    <table>
      <thead><tr><th>Source</th><th>Theme / Type</th><th>Scope</th><th>Count</th><th>Example</th></tr></thead>
      <tbody>
      {% for row in overview.threat_context[:10] %}
        <tr>
          <td>{{ row.source }}</td>
          <td>{{ row.theme_or_type }}</td>
          <td class="muted">{{ row.scope }}</td>
          <td>{{ row.count }}</td>
          <td class="muted">{{ row.examples[0].value if row.examples else '-' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="panel span-5">
    <h2>Browser / Software Vulnerability Context</h2>
    <table>
      <thead><tr><th>Vulnerability</th><th>Source</th><th>Status</th><th>Local match</th></tr></thead>
      <tbody>
      {% if not overview.vulnerability_context %}
        <tr>
          <td colspan="4" class="muted">
            No live vulnerability records currently match the observed browser/software inventory. Demo/sample matches are hidden from this overview.
          </td>
        </tr>
      {% endif %}
      {% for vuln in overview.vulnerability_context[:8] %}
        <tr>
          <td>
            {{ vuln.vuln_id }}
            {% if vuln.is_demo %}<span class="pill missing">demo</span>{% endif %}
          </td>
          <td>{{ vuln.source }}</td>
          <td>{{ vuln.match_status.replace('_', ' ') }}</td>
          <td>
            {% if vuln.matched_products %}
              {% for match in vuln.matched_products[:3] %}
                <span class="pill ok">{{ match.host }}: {{ match.product }} {{ match.version }}</span>
              {% endfor %}
            {% else %}
              <span class="muted">needs inventory confirmation</span>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</section>

<section class="grid" style="margin-top:16px">
  <div class="panel span-7">
    <h2>Service Exposure</h2>
    <table>
      <thead><tr><th>Host</th><th>Service</th><th>Port</th><th>Severity</th><th>Source</th><th>Use</th></tr></thead>
      <tbody>
      {% for service in overview.service_exposure[:8] %}
        <tr>
          <td>{{ service.host }}</td>
          <td>{{ service.service }}</td>
          <td>{{ service.port }}</td>
          <td>{% if service.severity %}<span class="pill warn">{{ service.severity }}</span>{% else %}-{% endif %}</td>
          <td>{{ service.source or 'manual' }}</td>
          <td class="muted">{{ service.correlation_use }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="panel span-5">
    <h2>Import Stored Collector Output</h2>
    <form method="post" action="{{ url_for('action_import') }}" class="formline">
      <div>
        <label>Type</label>
        <select name="kind">
          <option value="dnscap">DNScap DNS CSV/log root</option>
          <option value="enumeros">Enumeros JSON</option>
          <option value="safesniff">SafeSniff JSON</option>
        </select>
      </div>
      <div>
        <label>Path</label>
        <input type="text" name="path" placeholder="/path/to/output.json or /path/to/dns.csv">
      </div>
      <input type="submit" value="Import">
    </form>
  </div>
</section>

<section class="grid" style="margin-top:16px">
  <div class="panel span-7">
    <h2>Outputs</h2>
    <table class="compact">
      {% for item in outputs %}
      <tr><td>{{ item.name }}</td><td><span class="pill {{ 'ok' if item.exists else 'missing' }}">{{ 'present' if item.exists else 'missing' }}</span></td></tr>
      {% endfor %}
    </table>
  </div>
  <div class="panel span-5">
    <h2>Configured Paths</h2>
    <p class="paths"><strong>Project</strong><br>{{ paths.project_root }}</p>
    <p class="paths"><strong>Data</strong><br>{{ paths.data_dir }}</p>
    <p class="paths"><strong>Local context</strong><br>{{ paths.local_context_dir }}</p>
  </div>
</section>
"""


CONFIG_EDITOR = """
<section class="operator-bar">
  <form method="get" action="{{ url_for('config_page') }}" class="config-picker">
    <div>
      <label>Config set</label>
      <select name="set">
        {% for item in config_sets %}
          <option value="{{ item.name }}" {% if item.name == selected %}selected{% endif %}>
            {{ item.name }}{% if item.active %} (active){% endif %}
          </option>
        {% endfor %}
      </select>
    </div>
    <div>
      <label>New set</label>
      <input form="create-config-form" type="text" name="name" placeholder="incident-response">
    </div>
    <div class="actions">
      <input type="submit" value="Open">
      <input form="create-config-form" class="secondary" type="submit" value="Capture">
    </div>
  </form>
  <div class="operator-actions">
    <span id="validation-pill" class="pill {{ 'ok' if validation.valid else 'warn' }}">{{ 'ready' if validation.valid else 'check config' }}</span>
    <input form="config-save-form" type="submit" value="Save">
    <button form="config-save-form" class="secondary" type="submit" formaction="{{ url_for('config_apply') }}" formmethod="post">Apply</button>
    <a class="rail-link" href="{{ url_for('index') }}">Dashboard</a>
  </div>
</section>

<form id="create-config-form" method="post" action="{{ url_for('config_create') }}"></form>

<form id="config-save-form" method="post" action="{{ url_for('config_save') }}">
  <input type="hidden" name="config_set" value="{{ selected }}">
  <div class="operator-shell">
    <nav class="operator-rail">
      <a class="rail-link active" href="#sources">Sources</a>
      <a class="rail-link" href="#sensitivity">Sensitivity</a>
      <a class="rail-link" href="#advanced">Advanced</a>
      <a class="rail-link" href="#import">Import</a>
      <div class="rail-status">
        <h3>Validation</h3>
        <div id="validation-summary">{{ validation.summary }}</div>
        <ul id="validation-list" class="validation-list">
          {% for message in validation.messages %}
            <li>{{ message }}</li>
          {% endfor %}
        </ul>
      </div>
    </nav>

    <div class="workspace">
      <section id="sources" class="workspace-section">
        <div class="section-head">
          <h2>Sources</h2>
          <div class="section-kpis">
            {% for source in source_visual.sources %}
              <span class="pill {{ 'ok' if source.enabled else 'missing' }}">{{ source.label }}: {{ 'on' if source.enabled else 'off' }}</span>
            {% endfor %}
          </div>
        </div>
        <div class="source-grid" id="source-cards">
          {% for source in source_visual.sources %}
            <article class="source-card" data-source="{{ source.key }}">
              <header>
                <div>
                  <h3>{{ source.label }}</h3>
                  <div class="muted">{{ source.purpose }}</div>
                </div>
                <label class="switch">
                  <input type="checkbox" data-source-field="enabled" {% if source.enabled %}checked{% endif %}>
                  <span class="source-enabled-label">{{ 'On' if source.enabled else 'Off' }}</span>
                </label>
              </header>
              <div class="source-fields">
                <div>
                  <label>Collection</label>
                  <select data-source-field="mode">
                    {% for mode in source.modes %}
                      <option value="{{ mode }}" {% if mode == source.mode %}selected{% endif %}>{{ source.mode_labels.get(mode, mode) }}</option>
                    {% endfor %}
                  </select>
                </div>
                <div>
                  <label>Limit</label>
                  <input type="text" data-source-field="{{ source.limit_key }}" value="{{ source.limit_value }}">
                </div>
              </div>
              <div class="source-path">
                <label>{{ source.url_label }}</label>
                <input type="text" data-source-field="{{ source.url_key }}" value="{{ source.url_value }}">
              </div>
              <div class="source-counts">
                <span class="pill {{ 'ok' if source.enabled else 'missing' }}" data-source-state>{{ 'active' if source.enabled else 'off' }}</span>
                <span class="pill">{{ source.raw_count }} file(s)</span>
                <span class="pill">{{ source.raw_dir }}</span>
              </div>
            </article>
          {% endfor %}
        </div>
      </section>

      {% if scoring_file %}
      <section id="sensitivity" class="workspace-section">
        <div class="section-head">
          <h2>Sensitivity</h2>
          <div class="actions">
            <button class="secondary" type="button" id="sync-sources">Sync sources</button>
            <button class="secondary" type="button" id="sync-visual">Sync scoring</button>
            <button class="secondary" type="button" id="validate-now">Validate</button>
          </div>
        </div>
        <div class="quiet-panel">
          <div class="rule-groups" id="rule-groups">
            {% for group in scoring_visual.groups %}
              <section class="rule-group" data-rule-group="{{ group['key'] }}">
                <h3>{{ group['label'] }}</h3>
                {% for item in group['items'] %}
                  <div class="rule-row" data-rule-item="{{ item['section'] }}.{{ item['key'] }}">
                    <div class="rule-name">{{ item['label'] }}</div>
                    <input
                      type="range"
                      min="{{ item['min'] }}"
                      max="{{ item['max'] }}"
                      step="1"
                      value="{{ item['value'] }}"
                      data-section="{{ item['section'] }}"
                      data-key="{{ item['key'] }}"
                      aria-label="{{ item['label'] }}"
                    >
                    <div class="rule-value">{{ item['value'] }}</div>
                  </div>
                {% endfor %}
              </section>
            {% endfor %}
          </div>
        </div>
      </section>
      {% endif %}

      <section id="advanced" class="workspace-section">
        <div class="section-head">
          <h2>Advanced</h2>
          <div class="validation-strip">
            <span class="pill {{ 'ok' if validation.valid else 'warn' }}">{{ 'valid YAML' if validation.valid else 'YAML needs review' }}</span>
          </div>
        </div>
        <details class="yaml-drawer">
          <summary>Raw config files</summary>
          <div class="drawer-body">
            {% if scoring_file %}
              <div class="raw-file">
                <h3>{{ scoring_file.path }}</h3>
                <textarea id="scoring-yaml" class="compact-yaml" name="file:{{ scoring_file.path }}" rows="{{ scoring_file.rows }}" spellcheck="false">{{ scoring_file.text }}</textarea>
                <div class="file-validation muted" data-validation-for="{{ scoring_file.path }}">{{ validation.files.get(scoring_file.path, {}).get('summary', '') }}</div>
              </div>
            {% endif %}
            {% for file in other_files %}
              <div class="raw-file">
                <h3>{{ file.path }}</h3>
                <textarea name="file:{{ file.path }}" data-file-path="{{ file.path }}" rows="{{ file.rows }}" spellcheck="false">{{ file.text }}</textarea>
                <div class="file-validation muted" data-validation-for="{{ file.path }}">
                  {{ validation.files.get(file.path, {}).get('summary', '') }}
                </div>
              </div>
            {% endfor %}
          </div>
        </details>
      </section>
    </div>
  </div>
</form>

<section id="import" class="workspace-section" style="margin-top:22px">
  <div class="section-head">
    <h2>Import</h2>
  </div>
  <div class="quiet-panel">
    <form method="post" action="{{ url_for('config_import_source') }}" class="import-row">
      <input type="hidden" name="config_set" value="{{ selected }}">
      <div>
        <label>Source</label>
        <select name="source">
          {% for source in source_visual.sources %}
            <option value="{{ source.key }}">{{ source.label }}</option>
          {% endfor %}
        </select>
      </div>
      <div>
        <label>Local file or directory</label>
        <input type="text" name="path" placeholder="/path/to/source.jsonl or /path/to/raw-dir">
      </div>
      <input type="submit" value="Import">
    </form>
  </div>
</section>
<script>
(() => {
  const initialRules = {{ scoring_visual.rules | tojson }};
  const initialSources = {{ source_visual.config | tojson }};
  let rules = JSON.parse(JSON.stringify(initialRules || {}));
  let sourceConfig = JSON.parse(JSON.stringify(initialSources || {sources: {}}));
  const textarea = document.getElementById("scoring-yaml");
  const sourceTextarea = document.querySelector('textarea[name="file:config/source_config.yaml"]');
  const validationPill = document.getElementById("validation-pill");
  const validationSummary = document.getElementById("validation-summary");
  const validationList = document.getElementById("validation-list");

  function titleize(value) {
    return value.replaceAll("_", " ").replace(/\\b\\w/g, char => char.toUpperCase());
  }

  function toYaml(data) {
    const sections = ["source_weights", "relevance_boosts", "penalties", "priority_bands"];
    return sections
      .filter(section => data[section] && typeof data[section] === "object")
      .map(section => {
        const lines = [section + ":"];
        Object.entries(data[section]).forEach(([key, value]) => {
          lines.push("  " + key + ": " + Number(value));
        });
        return lines.join("\\n");
      })
      .join("\\n\\n") + "\\n";
  }

  function scalar(value) {
    if (value === true) return "true";
    if (value === false) return "false";
    if (value === null || value === undefined) return '""';
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    const text = String(value);
    if (/^[A-Za-z0-9_./:{}?=&-]+$/.test(text)) return text;
    return JSON.stringify(text);
  }

  function sourceConfigToYaml(config) {
    const sources = config.sources || {};
    const lines = ["sources:"];
    Object.entries(sources).forEach(([name, values]) => {
      lines.push("  " + name + ":");
      Object.entries(values || {}).forEach(([key, value]) => {
        lines.push("    " + key + ": " + scalar(value));
      });
    });
    return lines.join("\\n") + "\\n";
  }

  function updateMeter(input) {
    const row = input.closest(".rule-row");
    const value = row.querySelector(".rule-value");
    value.textContent = input.value;
    const max = Number(input.max);
    const min = Number(input.min);
    const pct = ((Number(input.value) - min) / Math.max(1, max - min)) * 100;
    input.style.backgroundSize = pct + "% 100%";
  }

  function slidersToYaml() {
    document.querySelectorAll("#rule-groups input[type=range]").forEach(input => {
      const section = input.dataset.section;
      const key = input.dataset.key;
      rules[section] = rules[section] || {};
      rules[section][key] = Number(input.value);
      updateMeter(input);
    });
    textarea.value = toYaml(rules);
    validateNow();
  }

  function sourceCardsToYaml() {
    document.querySelectorAll(".source-card").forEach(card => {
      const name = card.dataset.source;
      sourceConfig.sources = sourceConfig.sources || {};
      sourceConfig.sources[name] = sourceConfig.sources[name] || {};
      card.querySelectorAll("[data-source-field]").forEach(input => {
        const key = input.dataset.sourceField;
        if (input.type === "checkbox") {
          sourceConfig.sources[name][key] = input.checked;
        } else if (/^max_/.test(key)) {
          sourceConfig.sources[name][key] = Number(input.value || 0);
        } else {
          sourceConfig.sources[name][key] = input.value;
        }
      });
      updateSourceCardState(card);
    });
    if (sourceTextarea) {
      sourceTextarea.value = sourceConfigToYaml(sourceConfig);
      validateNow();
    }
  }

  function updateSourceCardState(card) {
    const enabled = card.querySelector('[data-source-field="enabled"]')?.checked;
    const label = card.querySelector('.source-enabled-label');
    const state = card.querySelector('[data-source-state]');
    if (label) label.textContent = enabled ? 'On' : 'Off';
    if (state) {
      state.textContent = enabled ? 'active' : 'off';
      state.className = 'pill ' + (enabled ? 'ok' : 'missing');
    }
  }

  function applyVisual(payload) {
    if (!payload || !payload.groups) return;
    rules = payload.rules || rules;
    payload.groups.forEach(group => {
      group.items.forEach(item => {
        const selector = `input[data-section="${item.section}"][data-key="${item.key}"]`;
        const input = document.querySelector(selector);
        if (input) {
          input.value = item.value;
          updateMeter(input);
        }
      });
    });
  }

  function applySourceVisual(payload) {
    if (!payload || !payload.sources) return;
    sourceConfig = payload.config || sourceConfig;
    payload.sources.forEach(source => {
      const card = document.querySelector(`.source-card[data-source="${source.key}"]`);
      if (!card) return;
      const enabled = card.querySelector('[data-source-field="enabled"]');
      if (enabled) enabled.checked = Boolean(source.enabled);
      const mode = card.querySelector('[data-source-field="mode"]');
      if (mode) mode.value = source.mode || "";
      const limit = card.querySelector(`[data-source-field="${source.limit_key}"]`);
      if (limit) limit.value = source.limit_value;
      const url = card.querySelector(`[data-source-field="${source.url_key}"]`);
      if (url) url.value = source.url_value || "";
    });
  }

  function setValidation(payload) {
    const ok = Boolean(payload && payload.valid);
    validationPill.textContent = ok ? "ready" : "check config";
    validationPill.className = "pill " + (ok ? "ok" : "warn");
    validationSummary.textContent = payload && payload.summary ? payload.summary : (ok ? "All checks passed." : "Validation failed.");
    validationList.innerHTML = "";
    const messages = payload && payload.messages ? payload.messages : [];
    messages.forEach(message => {
      const li = document.createElement("li");
      li.textContent = message;
      validationList.appendChild(li);
    });
    document.querySelectorAll("[data-validation-for]").forEach(node => {
      const item = payload && payload.files ? payload.files[node.dataset.validationFor] : null;
      node.textContent = item ? item.summary : "";
      node.className = "file-validation " + (item && !item.valid ? "warn" : "muted");
    });
  }

  let validateTimer = null;
  async function validateNow(syncVisual = false) {
    if (!textarea) return;
    const files = {"config/scoring_rules.yaml": textarea.value};
    document.querySelectorAll("textarea[name^='file:']").forEach(node => {
      files[node.name.slice(5)] = node.value;
    });
    const response = await fetch("{{ url_for('config_validate') }}", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({files})
    });
    const payload = await response.json();
    setValidation(payload);
    if (syncVisual && payload.scoring_visual) {
      applyVisual(payload.scoring_visual);
    }
    if (syncVisual && payload.source_visual) {
      applySourceVisual(payload.source_visual);
    }
  }

  document.querySelectorAll("#rule-groups input[type=range]").forEach(input => {
    updateMeter(input);
    input.addEventListener("input", slidersToYaml);
  });
  document.getElementById("validate-now")?.addEventListener("click", () => validateNow(true));
  document.getElementById("sync-visual")?.addEventListener("click", () => validateNow(true));
  document.getElementById("sync-sources")?.addEventListener("click", () => validateNow(true));
  document.querySelectorAll(".source-card input, .source-card select").forEach(input => {
    input.addEventListener("input", sourceCardsToYaml);
    input.addEventListener("change", sourceCardsToYaml);
  });
  textarea?.addEventListener("input", () => {
    clearTimeout(validateTimer);
    validateTimer = setTimeout(() => validateNow(false), 400);
  });
})();
</script>
"""


VALIDATION_PAGE = """
<section class="operator-bar">
  <div>
    <h2>ThreatSucker Validation</h2>
    <p class="muted">
      Runs isolated correlation checks against synthetic local evidence and threat intel. This validates the reduction engine,
      scoring rules, allowlist handling, and vulnerability matching without changing live project evidence.
    </p>
  </div>
  <div class="operator-actions">
    <form method="post" action="{{ url_for('validation_run') }}">
      <input type="submit" value="Run validation suite">
    </form>
    <a class="rail-link" href="{{ url_for('config_page') }}">Config</a>
    <a class="rail-link" href="{{ url_for('index') }}">Dashboard</a>
  </div>
</section>

{% if not results %}
  <section class="panel" style="margin-top:16px">
    <h2>No validation run yet</h2>
    <p class="muted">Run the suite to create a controlled evidence pack and check the correlation outputs.</p>
  </section>
{% else %}
  <section class="result-kpis">
    <div class="result-kpi"><strong>{{ results.summary.total }}</strong><span class="muted">cases</span></div>
    <div class="result-kpi"><strong>{{ results.summary.passed }}</strong><span class="muted">passed</span></div>
    <div class="result-kpi"><strong>{{ results.summary.failed }}</strong><span class="muted">failed</span></div>
    <div class="result-kpi"><strong>{{ results.summary.relevant_indicators }}</strong><span class="muted">relevant indicators</span></div>
  </section>

  <section class="validation-grid">
    <div class="case-list">
      {% for case in results.cases %}
        <article class="case-card {{ 'pass' if case.passed else 'fail' }}">
          <div class="case-title">
            <strong>{{ case.name }}</strong>
            <span class="pill {{ 'ok' if case.passed else 'warn' }}">{{ 'pass' if case.passed else 'fail' }}</span>
          </div>
          <p class="muted">{{ case.description }}</p>
          <table class="compact">
            <tr><td>Expected</td><td>{{ case.expected }}</td></tr>
            <tr><td>Actual</td><td>{{ case.actual }}</td></tr>
            {% if case.score is not none %}<tr><td>Score</td><td>{{ case.score }}</td></tr>{% endif %}
            {% if case.priority %}<tr><td>Priority</td><td>{{ case.priority }}</td></tr>{% endif %}
          </table>
          {% if case.messages %}
            <ul class="validation-list">
              {% for message in case.messages %}<li>{{ message }}</li>{% endfor %}
            </ul>
          {% endif %}
        </article>
      {% endfor %}
    </div>
    <div class="panel">
      <h2>Pipeline Output</h2>
      <p class="paths"><strong>Workspace</strong><br>{{ results.workspace }}</p>
      <table class="compact">
        <tr><td>Normalized indicators</td><td>{{ results.summary.normalized_indicators }}</td></tr>
        <tr><td>Normalized vulnerabilities</td><td>{{ results.summary.normalized_vulnerabilities }}</td></tr>
        <tr><td>Relevant vulnerabilities</td><td>{{ results.summary.relevant_vulnerabilities }}</td></tr>
      </table>
      <pre class="validation-json">{{ results | tojson(indent=2) }}</pre>
    </div>
  </section>
{% endif %}
"""


def _config_editor_files(paths: ProjectPaths, config_set: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for rel in CONFIG_FILES:
        text = read_config_file(paths, config_set, rel)
        files.append(
            {
                "path": str(rel),
                "text": text,
                "rows": max(8, min(22, text.count("\n") + 3)),
            }
        )
    return files


YAML_CONFIG_FILES = {
    "config/org_profile.yaml",
    "config/scoring_rules.yaml",
    "config/source_config.yaml",
    "local_context/org/org_profile.yaml",
    "local_context/users/competency_profile.yaml",
}

SCORING_GROUPS = [
    ("source_weights", "Source Weights", 0, 60),
    ("relevance_boosts", "Relevance Boosts", 0, 60),
    ("penalties", "Noise Penalties", -100, 0),
    ("priority_bands", "Priority Bands", 0, 100),
]

REQUIRED_SCORING_SECTIONS = {group[0] for group in SCORING_GROUPS}

SOURCE_DEFINITIONS = {
    "misp_osint": {
        "label": "MISP OSINT",
        "purpose": "Campaign indicators",
        "raw_dir": "misp",
        "patterns": ["*.json"],
        "limit_key": "max_events",
        "url_key": "url",
        "url_label": "Feed URL",
        "modes": ["live_or_fixture", "live", "fixture", "imported_only"],
    },
    "circl_vulnerability_lookup": {
        "label": "CIRCL Vulnerability Lookup",
        "purpose": "Software vulnerabilities",
        "raw_dir": "vulnerability_lookup",
        "patterns": ["*.jsonl"],
        "limit_key": "max_records",
        "url_key": "url",
        "url_label": "API URL",
        "modes": ["live_or_fixture", "live", "fixture", "imported_only"],
    },
    "phishtank": {
        "label": "PhishTank",
        "purpose": "Phishing URLs",
        "raw_dir": "phishtank",
        "patterns": ["*.json"],
        "limit_key": "max_records",
        "url_key": "data_url_template",
        "url_label": "Data URL Template",
        "modes": ["live_optional_key_or_fixture", "live", "fixture", "imported_only"],
    },
    "urlhaus": {
        "label": "URLhaus",
        "purpose": "Malware URLs",
        "raw_dir": "urlhaus",
        "patterns": ["*.jsonl"],
        "limit_key": "max_records",
        "url_key": "url",
        "url_label": "API URL",
        "modes": ["live_or_fixture", "live", "fixture", "imported_only"],
    },
}

SOURCE_MODE_LABELS = {
    "live_or_fixture": "Live, fallback to stored",
    "live_optional_key_or_fixture": "Live with key, fallback to stored",
    "live": "Live only",
    "fixture": "Stored demo only",
    "imported_only": "Imported only",
}


def _run_validation_suite(paths: ProjectPaths) -> dict[str, Any]:
    validation_root = paths.data_dir / "validation_runs" / "current"
    if validation_root.exists():
        shutil.rmtree(validation_root)
    validation_paths = ProjectPaths(validation_root)
    _prepare_validation_workspace(paths, validation_paths)

    normalized_indicators, normalized_vulnerabilities = normalize_all(validation_paths)
    scored_indicators, scored_vulnerabilities = score_all(validation_paths)

    by_value = {item.value: item for item in scored_indicators}
    by_vuln = {item.vuln_id: item for item in scored_vulnerabilities}
    phishing = by_value.get("login-micros0ft-security.com")
    allowlisted = by_value.get("microsoft.com")
    chrome_vuln = by_vuln.get("CVE-2026-54321")

    cases = [
        _validation_case(
            name="DNS threat correlation",
            description="A phishing domain from MISP is also present in observed DNS context, so it should score as a high/critical local match.",
            expected="priority high or critical, with a dns: matched_local_data entry",
            actual=_indicator_actual(phishing),
            passed=bool(
                phishing
                and phishing.priority in {"high", "critical"}
                and any(str(match).startswith("dns:") for match in phishing.matched_local_data)
            ),
            score=phishing.score if phishing else None,
            priority=phishing.priority if phishing else None,
        ),
        _validation_case(
            name="Allowlist suppression",
            description="A benign allowlisted domain appears in DNS and intel, but the allowlist should stop it becoming actionable.",
            expected="priority archive or low, never medium/high/critical",
            actual=_indicator_actual(allowlisted),
            passed=bool(allowlisted and allowlisted.priority in {"archive", "low"} and allowlisted.score <= 20),
            score=allowlisted.score if allowlisted else None,
            priority=allowlisted.priority if allowlisted else None,
        ),
        _validation_case(
            name="Vulnerability inventory match",
            description="A Chrome vulnerability should correlate to a Chrome browser version in local inventory.",
            expected="priority high or critical, with at least one matched asset",
            actual=_vulnerability_actual(chrome_vuln),
            passed=bool(chrome_vuln and chrome_vuln.priority in {"high", "critical"} and chrome_vuln.matched_assets),
            score=chrome_vuln.score if chrome_vuln else None,
            priority=chrome_vuln.priority if chrome_vuln else None,
        ),
    ]

    result = {
        "status": "pass" if all(case["passed"] for case in cases) else "fail",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "workspace": str(validation_root),
        "summary": {
            "total": len(cases),
            "passed": sum(1 for case in cases if case["passed"]),
            "failed": sum(1 for case in cases if not case["passed"]),
            "normalized_indicators": len(normalized_indicators),
            "normalized_vulnerabilities": len(normalized_vulnerabilities),
            "relevant_indicators": sum(1 for item in scored_indicators if item.priority != "archive"),
            "relevant_vulnerabilities": sum(1 for item in scored_vulnerabilities if item.priority != "archive"),
        },
        "cases": cases,
        "evidence_files": {
            "misp": str(validation_paths.raw_dir / "misp" / "validation_campaign.json"),
            "vulnerabilities": str(validation_paths.raw_dir / "vulnerability_lookup" / "validation_vulnerabilities.jsonl"),
            "dns": str(validation_paths.local_context_dir / "dns" / "current" / "queries.csv"),
            "browsers": str(validation_paths.local_context_dir / "assets" / "browsers.csv"),
        },
    }
    result_path = validation_root / "validation_result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def _prepare_validation_workspace(source_paths: ProjectPaths, validation_paths: ProjectPaths) -> None:
    validation_paths.project_root.mkdir(parents=True, exist_ok=True)
    _copy_or_write_config(source_paths, validation_paths)
    _write_validation_local_context(validation_paths)
    _write_validation_raw_intel(validation_paths)


def _copy_or_write_config(source_paths: ProjectPaths, validation_paths: ProjectPaths) -> None:
    validation_paths.config_dir.mkdir(parents=True, exist_ok=True)
    defaults = {
        "org_profile.yaml": """org_name: Validation NGO
country: Luxembourg
languages: [en, fr]
sector: nonprofit
handles_sensitive_data: true
handles_donor_data: true
has_public_donation_page: true
uses_cloud_email: true
likely_targets: [phishing, credential_theft, invoice_fraud]
technical_capacity: low
""",
        "scoring_rules.yaml": """source_weights:
  misp: 40
  vulnerability_lookup: 40
relevance_boosts:
  matched_dns_query: 40
  matched_org_domain: 35
  targeted_brand_used_by_org: 25
  recent_7_days: 20
  recent_30_days: 10
  luxembourg_related: 25
  neighbouring_country_related: 10
  credential_theft: 20
  ransomware: 25
  c2_or_malware_distribution: 25
  low_user_competency_environment: 15
  matched_asset_software: 40
  exploit_available: 20
  known_exploited: 35
penalties:
  low_confidence: -20
  stale_older_than_90_days: -25
  no_local_match: -20
  allowlisted_domain: -100
priority_bands:
  critical: 90
  high: 70
  medium: 45
  low: 20
  archive: 0
""",
        "source_config.yaml": """sources:
  misp_osint:
    enabled: true
    mode: imported_only
    url: ""
    max_events: 20
  circl_vulnerability_lookup:
    enabled: true
    mode: imported_only
    url: ""
    max_records: 20
  phishtank:
    enabled: false
    mode: imported_only
    data_url_template: ""
    max_records: 0
  urlhaus:
    enabled: false
    mode: imported_only
    url: ""
    max_records: 0
""",
        "allowlist_domains.txt": "microsoft.com\nexample.com\n",
    }
    for name, fallback in defaults.items():
        source = source_paths.config_dir / name
        target = validation_paths.config_dir / name
        if source.exists() and name in {"org_profile.yaml", "scoring_rules.yaml"}:
            shutil.copy2(source, target)
        else:
            target.write_text(fallback, encoding="utf-8")


def _write_validation_local_context(paths: ProjectPaths) -> None:
    (paths.local_context_dir / "org").mkdir(parents=True, exist_ok=True)
    (paths.local_context_dir / "assets").mkdir(parents=True, exist_ok=True)
    (paths.local_context_dir / "dns" / "current").mkdir(parents=True, exist_ok=True)
    (paths.local_context_dir / "org" / "brands_used.txt").write_text("Microsoft 365\nPayPal\n", encoding="utf-8")
    (paths.local_context_dir / "org" / "domains.txt").write_text("validation-ngo.lu\n", encoding="utf-8")
    _write_csv(
        paths.local_context_dir / "dns" / "current" / "queries.csv",
        ["timestamp", "host", "queried_domain", "query_type", "source"],
        [
            {
                "timestamp": "2026-05-27T10:00:00Z",
                "host": "finance-laptop-01",
                "queried_domain": "login-micros0ft-security.com",
                "query_type": "A",
                "source": "validation-dnscap",
            },
            {
                "timestamp": "2026-05-27T10:01:00Z",
                "host": "finance-laptop-01",
                "queried_domain": "microsoft.com",
                "query_type": "A",
                "source": "validation-dnscap",
            },
        ],
    )
    _write_csv(
        paths.local_context_dir / "assets" / "browsers.csv",
        ["host", "browser", "version", "source"],
        [{"host": "finance-laptop-01", "browser": "Chrome", "version": "123.0.6312.86", "source": "validation"}],
    )
    for name, headers in {
        "hosts.csv": ["host", "os", "source"],
        "software.csv": ["host", "product", "version", "source"],
        "services.csv": ["host", "service", "port", "source"],
        "exposed_ports.csv": ["host", "port", "service", "severity", "source"],
    }.items():
        _write_csv(paths.local_context_dir / "assets" / name, headers, [])


def _write_validation_raw_intel(paths: ProjectPaths) -> None:
    misp_dir = paths.raw_dir / "misp"
    vuln_dir = paths.raw_dir / "vulnerability_lookup"
    misp_dir.mkdir(parents=True, exist_ok=True)
    vuln_dir.mkdir(parents=True, exist_ok=True)
    campaign = {
        "Event": {
            "uuid": "validation-correlation-campaign",
            "info": "Validation phishing campaign targeting Microsoft 365 in Luxembourg",
            "timestamp": "1779523920",
            "Tag": [{"name": "phishing"}, {"name": "credential-theft"}, {"name": "Luxembourg"}],
            "Attribute": [
                {
                    "uuid": "validation-domain-1",
                    "category": "Network activity",
                    "type": "domain",
                    "value": "login-micros0ft-security.com",
                    "comment": "Microsoft 365 lookalike credential theft validation domain",
                    "to_ids": True,
                    "timestamp": "1779523920",
                },
                {
                    "uuid": "validation-domain-2",
                    "category": "Network activity",
                    "type": "domain",
                    "value": "microsoft.com",
                    "comment": "Allowlist suppression validation domain",
                    "to_ids": True,
                    "timestamp": "1779523920",
                },
            ],
        }
    }
    (misp_dir / "validation_campaign.json").write_text(json.dumps(campaign, indent=2), encoding="utf-8")
    vuln_record = {
        "cve": "CVE-2026-54321",
        "title": "Validation Chrome browser remote code execution vulnerability",
        "description": "Synthetic validation record for Chrome inventory matching.",
        "affected_products": [{"vendor": "Google", "product": "Chrome", "version": "123.0.6312.86"}],
        "cvss": 9.4,
        "exploit_available": True,
        "known_exploited": True,
        "published": "2026-05-01T00:00:00Z",
        "modified": "2026-05-02T00:00:00Z",
        "references": ["https://example.org/validation/CVE-2026-54321"],
    }
    (vuln_dir / "validation_vulnerabilities.jsonl").write_text(json.dumps(vuln_record) + "\n", encoding="utf-8")


def _write_csv(path: Path, headers: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({header: row.get(header, "") for header in headers})


def _validation_case(
    *,
    name: str,
    description: str,
    expected: str,
    actual: str,
    passed: bool,
    score: int | None,
    priority: str | None,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "score": score,
        "priority": priority,
        "messages": [] if passed else ["Expected condition was not met."],
    }


def _indicator_actual(item: Any) -> str:
    if item is None:
        return "No scored indicator found."
    return f"{item.value} scored {item.score} as {item.priority}; matches={', '.join(item.matched_local_data) or 'none'}"


def _vulnerability_actual(item: Any) -> str:
    if item is None:
        return "No scored vulnerability found."
    return f"{item.vuln_id} scored {item.score} as {item.priority}; matched_assets={', '.join(item.matched_assets) or 'none'}"


def _save_config_form(paths: ProjectPaths, selected: str) -> None:
    files = {str(rel): request.form.get(f"file:{rel}", "") for rel in CONFIG_FILES}
    validation = _validate_config_payload(files)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["messages"]))
    for rel in CONFIG_FILES:
        write_config_file(paths, selected, rel, files[str(rel)])


def _validate_config_payload(files: dict[str, str]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    all_messages: list[str] = []
    valid = True
    for rel, text in files.items():
        item = _validate_one_config_file(rel, text)
        results[rel] = item
        if not item["valid"]:
            valid = False
        all_messages.extend(f"{rel}: {message}" for message in item["messages"])
    return {
        "valid": valid,
        "files": results,
        "messages": all_messages,
        "summary": "All checks passed." if valid else f"{len(all_messages)} issue(s) found.",
    }


def _validate_one_config_file(rel: str, text: str) -> dict[str, Any]:
    messages: list[str] = []
    warnings: list[str] = []
    data: Any = None
    if rel in YAML_CONFIG_FILES:
        try:
            data = yaml.safe_load(text) if text.strip() else {}
        except yaml.YAMLError as exc:
            return {
                "valid": False,
                "summary": f"YAML error: {exc}",
                "messages": [f"YAML error: {exc}"],
                "warnings": [],
            }
        if data is None:
            data = {}
        if not isinstance(data, dict):
            messages.append("Top-level YAML value must be a mapping.")
    if rel == "config/scoring_rules.yaml" and isinstance(data, dict):
        score_messages, score_warnings = _validate_scoring_rules(data)
        messages.extend(score_messages)
        warnings.extend(score_warnings)
    if rel == "config/source_config.yaml" and isinstance(data, dict):
        source_messages, source_warnings = _validate_source_config(data)
        messages.extend(source_messages)
        warnings.extend(source_warnings)
    if rel.endswith(".txt") and not text.strip():
        warnings.append("File is empty.")
    return {
        "valid": not messages,
        "summary": "Valid" if not messages else f"{len(messages)} issue(s)",
        "messages": messages,
        "warnings": warnings,
    }


def _validate_scoring_rules(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    messages: list[str] = []
    warnings: list[str] = []
    missing = sorted(REQUIRED_SCORING_SECTIONS - set(data))
    if missing:
        messages.append("Missing section(s): " + ", ".join(missing))
    for section in sorted(REQUIRED_SCORING_SECTIONS & set(data)):
        if not isinstance(data.get(section), dict):
            messages.append(f"{section} must be a mapping.")
            continue
        for key, value in data[section].items():
            if not isinstance(value, int):
                messages.append(f"{section}.{key} must be an integer.")
                continue
            if section == "penalties" and value > 0:
                messages.append(f"{section}.{key} should be zero or negative.")
            if section != "penalties" and value < 0:
                messages.append(f"{section}.{key} should be zero or positive.")
            if abs(value) > 100:
                warnings.append(f"{section}.{key} is outside the normal -100 to 100 range.")
    bands = data.get("priority_bands", {})
    if isinstance(bands, dict):
        ordered = ["critical", "high", "medium", "low", "archive"]
        band_values = [bands.get(key) for key in ordered]
        if all(isinstance(value, int) for value in band_values):
            if not all(int(band_values[i]) >= int(band_values[i + 1]) for i in range(len(band_values) - 1)):
                messages.append("priority_bands must descend from critical to archive.")
            if int(band_values[-1]) != 0:
                warnings.append("priority_bands.archive is usually 0.")
    boosts = data.get("relevance_boosts", {})
    if isinstance(boosts, dict):
        dns = boosts.get("matched_dns_query")
        brand = boosts.get("targeted_brand_used_by_org")
        if isinstance(dns, int) and isinstance(brand, int) and dns < brand:
            warnings.append("matched_dns_query is lower than targeted_brand_used_by_org.")
    return messages, warnings


def _validate_source_config(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    messages: list[str] = []
    warnings: list[str] = []
    sources = data.get("sources")
    if not isinstance(sources, dict):
        return ["sources must be a mapping."], warnings
    for name, values in sources.items():
        if not isinstance(values, dict):
            messages.append(f"sources.{name} must be a mapping.")
            continue
        enabled = values.get("enabled")
        if not isinstance(enabled, bool):
            messages.append(f"sources.{name}.enabled must be true or false.")
        definition = SOURCE_DEFINITIONS.get(str(name))
        if not definition:
            warnings.append(f"sources.{name} is not a built-in visual source; YAML will still be preserved.")
            continue
        limit_key = str(definition["limit_key"])
        if limit_key in values and not isinstance(values.get(limit_key), int):
            messages.append(f"sources.{name}.{limit_key} must be an integer.")
        mode = values.get("mode")
        if mode and str(mode) not in definition["modes"]:
            warnings.append(f"sources.{name}.mode is not one of the known modes for the visual editor.")
    return messages, warnings


def _scoring_visual(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    groups: list[dict[str, Any]] = []
    for section, label, minimum, maximum in SCORING_GROUPS:
        values = data.get(section, {})
        if not isinstance(values, dict):
            values = {}
        items = [
            {
                "section": section,
                "key": str(key),
                "label": _human_label(str(key)),
                "value": int(value) if isinstance(value, int) else 0,
                "min": minimum,
                "max": maximum,
            }
            for key, value in values.items()
        ]
        groups.append({"key": section, "label": label, "items": items})
    return {"rules": data, "groups": groups}


def _human_label(value: str) -> str:
    return value.replace("_", " ").title()


def _source_visual(text: str, paths: ProjectPaths) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    sources = data.setdefault("sources", {})
    if not isinstance(sources, dict):
        sources = {}
        data["sources"] = sources
    items: list[dict[str, Any]] = []
    for key, definition in SOURCE_DEFINITIONS.items():
        values = sources.get(key, {})
        if not isinstance(values, dict):
            values = {}
        limit_key = str(definition["limit_key"])
        url_key = str(definition["url_key"])
        raw_dir = str(definition["raw_dir"])
        items.append(
            {
                "key": key,
                "label": definition["label"],
                "purpose": definition["purpose"],
                "enabled": bool(values.get("enabled", False)),
                "mode": str(values.get("mode", definition["modes"][0])),
                "modes": definition["modes"],
                "mode_labels": SOURCE_MODE_LABELS,
                "limit_key": limit_key,
                "limit_value": values.get(limit_key, 0),
                "url_key": url_key,
                "url_label": definition["url_label"],
                "url_value": values.get(url_key, ""),
                "raw_dir": raw_dir,
                "raw_count": _raw_source_count(paths, key),
            }
        )
    return {"config": data, "sources": items}


def _raw_source_count(paths: ProjectPaths, source_key: str) -> int:
    definition = SOURCE_DEFINITIONS.get(source_key)
    if not definition:
        return 0
    base = paths.raw_dir / str(definition["raw_dir"])
    if not base.exists():
        return 0
    patterns = definition["patterns"]
    return sum(1 for pattern in patterns for _ in base.rglob(str(pattern)))


def _import_source_files(paths: ProjectPaths, source_key: str, source_path: Path) -> int:
    definition = SOURCE_DEFINITIONS.get(source_key)
    if not definition:
        raise ValueError(f"Unsupported source: {source_key}")
    source_path = source_path.expanduser()
    if not source_path.exists():
        raise ValueError(f"Input path does not exist: {source_path}")
    destination = paths.raw_source_date_dir(str(definition["raw_dir"]))
    destination.mkdir(parents=True, exist_ok=True)
    patterns = [str(pattern) for pattern in definition["patterns"]]
    candidates: list[Path] = []
    if source_path.is_file():
        candidates = [source_path]
    else:
        for pattern in patterns:
            candidates.extend(sorted(source_path.rglob(pattern)))
    copied = 0
    for candidate in candidates:
        if not any(candidate.match(pattern) for pattern in patterns):
            continue
        target = destination / candidate.name
        if target.exists():
            target = destination / f"{candidate.stem}-{copied + 1}{candidate.suffix}"
        shutil.copy2(candidate, target)
        copied += 1
    if copied == 0:
        raise ValueError(f"No compatible files found for {source_key}: {', '.join(patterns)}")
    return copied


def _output_status(mini_dir: Path) -> list[dict[str, Any]]:
    names = [
        "ai_context.md",
        "ai_context.json",
        "ngo_relevance_brief.md",
        "ngo_relevance_brief.json",
        "deep_evidence.json",
        "dnscap_highlights.jsonl",
        "enumeros_findings.jsonl",
    ]
    return [{"name": name, "path": str(mini_dir / name), "exists": (mini_dir / name).exists()} for name in names]


def _collector_status(paths: ProjectPaths) -> dict[str, Any]:
    tools = [
        {"name": "dnscap", "available": shutil.which("dnscap") is not None},
        {"name": "enumeros", "available": shutil.which("enumeros") is not None},
        {"name": "safesniff", "available": shutil.which("safesniff") is not None},
    ]
    stored = {
        "enumeros": len(list((paths.local_context_dir / "imported" / "enumeros").glob("*.json"))),
        "safesniff": len(list((paths.local_context_dir / "imported" / "safesniff").glob("*.json"))),
    }
    return {"tools": tools, "stored_outputs": stored}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {"error": f"JSON file is empty: {path}"}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON in {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}"}
    return data if isinstance(data, dict) else {"error": f"Expected JSON object in {path}, got {type(data).__name__}"}


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def run_web(project_root: str | Path | None = None, host: str = "127.0.0.1", port: int = 8765, debug: bool = False) -> None:
    create_app(project_root).run(host=host, port=port, debug=debug)
