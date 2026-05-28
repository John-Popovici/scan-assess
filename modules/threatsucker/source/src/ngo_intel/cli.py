from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from .agent_brief import generate_agent_context
from .config import load_scoring_rules
from .config_sets import (
    apply_config_overrides,
    apply_config_set,
    ensure_default_config_set,
    list_config_sets,
    save_active_as_config_set,
)
from .explain import explain_indicator
from .io_utils import ensure_dir, read_jsonl
from .io_utils import write_csv
from .live_collect import collect_live_sources
from .local_context.loader import load_local_context
from .local_context.dns import read_dnscap_tree
from .local_context.dnscap_highlight import highlight_current_mini
from .local_context.enumeros_filter import filter_enumeros_documents, run_enumeros_binary
from .local_context.importers import CollectorJsonError, import_enumeros_json, import_safesniff_json
from .models import ScoredIndicator
from .mini import list_mini_profiles, run_mini
from .ngo_brief import build_ngo_relevance_brief
from .normalize import normalize_all
from .overview import build_overview
from .paths import ProjectPaths
from .scoring import score_all

app = typer.Typer(help="ThreatSucker: collect and reduce threat context for NGO-facing AI workflows.")
show_app = typer.Typer(help="Show generated triage outputs.")
mini_app = typer.Typer(help="Mini mode: profile-based collection with no scoring.")
smart_app = typer.Typer(help="Smart mode: local-context scoring and agent brief generation.")
config_app = typer.Typer(help="Manage named config sets.")
app.add_typer(show_app, name="show")
app.add_typer(mini_app, name="mini")
app.add_typer(smart_app, name="smart")
app.add_typer(config_app, name="config")
console = Console()


def _paths() -> ProjectPaths:
    load_dotenv()
    return ProjectPaths.discover()


@app.command()
def init() -> None:
    """Create directories and seed fixture-like raw/local files if missing."""
    paths = _paths()
    for directory in [
        paths.config_dir,
        paths.config_dir / "profiles",
        paths.data_dir / "state",
        paths.raw_dir / "misp",
        paths.raw_dir / "urlhaus",
        paths.raw_dir / "phishtank",
        paths.raw_dir / "vulnerability_lookup",
        paths.normalized_dir,
        paths.scored_dir,
        paths.agent_context_dir / "current",
        paths.local_context_dir / "org",
        paths.local_context_dir / "assets",
        paths.local_context_dir / "dns" / "current",
        paths.local_context_dir / "users",
    ]:
        ensure_dir(directory)
    for state_file in ["last_run.json", "source_etags.json", "seen_indicators.json"]:
        path = paths.data_dir / "state" / state_file
        if not path.exists():
            path.write_text("{}\n", encoding="utf-8")

    fixture_dir = paths.project_root / "tests" / "fixtures"
    copies = {
        fixture_dir / "misp_event_sample.json": paths.raw_dir / "misp" / "misp_event_sample.json",
        fixture_dir / "urlhaus_sample.jsonl": paths.raw_dir / "urlhaus" / "urlhaus_sample.jsonl",
        fixture_dir / "phishtank_lookup_sample.json": paths.raw_dir / "phishtank" / "phishtank_lookup_sample.json",
        fixture_dir / "vulnerability_lookup_sample.jsonl": paths.raw_dir / "vulnerability_lookup" / "vulnerability_lookup_sample.jsonl",
    }
    for src, dst in copies.items():
        if src.exists() and not dst.exists():
            shutil.copyfile(src, dst)
    console.print(f"[green]Initialized ngo-intel workspace:[/] {paths.project_root}")


@app.command("modes")
def modes() -> None:
    """Show the available ThreatSucker modes."""
    table = Table(title="ThreatSucker Modes")
    table.add_column("Mode")
    table.add_column("Purpose")
    table.add_column("Main command")
    table.add_row("mini", "Profile-matched threat context, no scoring, no local personalization.", "threatsucker mini run")
    table.add_row("smart", "Normalize, score against local context, and generate a triage brief.", "threatsucker smart run")
    console.print(table)


@app.command()
def normalize() -> None:
    """Normalize raw/fixture evidence into CSV and JSONL analyst data."""
    paths = _paths()
    indicators, vulnerabilities = normalize_all(paths)
    console.print(f"Normalized {len(indicators)} indicators and {len(vulnerabilities)} vulnerabilities.")


@app.command()
def score() -> None:
    """Score normalized intelligence against local NGO context."""
    paths = _paths()
    indicators, vulnerabilities = score_all(paths)
    console.print(f"Scored {len(indicators)} indicators and {len(vulnerabilities)} vulnerabilities.")


@app.command()
def brief() -> None:
    """Generate compact current agent context."""
    paths = _paths()
    generate_agent_context(paths)
    console.print(f"Wrote agent context to {paths.agent_context_dir / 'current'}")


def _prepare_config(
    paths: ProjectPaths,
    *,
    config_set: str | None = None,
    org_profile: Path | None = None,
    scoring_rules: Path | None = None,
    source_config: Path | None = None,
    allowlist: Path | None = None,
    brands: Path | None = None,
    domains: Path | None = None,
) -> None:
    ensure_default_config_set(paths)
    if config_set:
        selected = apply_config_set(paths, config_set)
        console.print(f"Applied config set: {selected.name}")
    applied = apply_config_overrides(
        paths,
        org_profile=org_profile,
        scoring_rules=scoring_rules,
        source_config=source_config,
        allowlist=allowlist,
        brands=brands,
        domains=domains,
    )
    if applied:
        console.print("Applied config override(s): " + ", ".join(applied))


def _run_pipeline(paths: ProjectPaths) -> tuple[int, int, int, int]:
    indicators, vulnerabilities = normalize_all(paths)
    scored_indicators, scored_vulns = score_all(paths)
    generate_agent_context(paths)
    return len(indicators), len(vulnerabilities), len(scored_indicators), len(scored_vulns)


@app.command()
def run(
    config_set: str | None = typer.Option(None, "--config-set", help="Apply a named config set before running."),
    org_profile: Path | None = typer.Option(None, "--org-profile", help="Override config/org_profile.yaml for this run."),
    scoring_rules: Path | None = typer.Option(None, "--scoring-rules", help="Override config/scoring_rules.yaml for this run."),
    source_config: Path | None = typer.Option(None, "--source-config", help="Override config/source_config.yaml for this run."),
    allowlist: Path | None = typer.Option(None, "--allowlist", help="Override config/allowlist_domains.txt for this run."),
    brands: Path | None = typer.Option(None, "--brands", help="Override local_context/org/brands_used.txt for this run."),
    domains: Path | None = typer.Option(None, "--domains", help="Override local_context/org/domains.txt for this run."),
) -> None:
    """Run smart mode for backward compatibility."""
    paths = _paths()
    _prepare_config(
        paths,
        config_set=config_set,
        org_profile=org_profile,
        scoring_rules=scoring_rules,
        source_config=source_config,
        allowlist=allowlist,
        brands=brands,
        domains=domains,
    )
    indicator_count, vulnerability_count, scored_indicator_count, scored_vuln_count = _run_pipeline(paths)
    console.print(
        f"[green]Pipeline complete.[/] normalized={indicator_count} indicators/{vulnerability_count} vulnerabilities; "
        f"scored={scored_indicator_count} indicators/{scored_vuln_count} vulnerabilities"
    )


@mini_app.command("profiles")
def mini_profiles() -> None:
    """List available mini profiles."""
    profiles = list_mini_profiles(_paths())
    table = Table(title="Mini Profiles")
    table.add_column("Profile")
    table.add_column("Name")
    table.add_column("Focus")
    for profile in profiles:
        table.add_row(profile.profile_id, profile.name, ", ".join(profile.threat_focus))
    console.print(table)


@mini_app.command("run")
def mini_run(profile: str = typer.Option("luxembourg_ngo", "--profile", help="Mini profile id.")) -> None:
    """Build a no-scoring AI context pack for a mini profile."""
    paths = _paths()
    counts = run_mini(paths, profile)
    console.print(
        f"[green]Mini mode complete.[/] profile={profile}; "
        f"normalized={counts['normalized_indicators']} indicators/{counts['normalized_vulnerabilities']} vulnerabilities; "
        f"included={counts['included_items']} items"
    )
    console.print(f"Output: {paths.data_dir / 'mini' / 'current'}")


@mini_app.command("collect-live")
def mini_collect_live(
    profile: str = typer.Option("luxembourg_ngo", "--profile", help="Mini profile id."),
    build_pack: bool = typer.Option(True, "--build-pack/--no-build-pack", help="Build the mini context pack after collection."),
) -> None:
    """Fetch live public intel, then optionally build the mini context pack."""
    paths = _paths()
    summary = collect_live_sources(paths, profile)
    for source, result in summary["sources"].items():
        console.print(f"{source}: {result}")
    if build_pack:
        counts = run_mini(paths, profile)
        console.print(f"[green]Mini pack rebuilt.[/] included={counts['included_items']} items")
        brief_counts = build_ngo_relevance_brief(paths)
        console.print(f"[green]NGO relevance brief rebuilt.[/] items={brief_counts['brief_items']}")


@app.command("collect-live")
def collect_live(
    profile: str = typer.Option("luxembourg_ngo", "--profile", help="Mini profile id."),
) -> None:
    """Fetch live public intel for mini mode and rebuild the context pack."""
    mini_collect_live(profile=profile, build_pack=True)


@mini_app.command("ngo-brief")
def mini_ngo_brief() -> None:
    """Build a general Luxembourg NGO relevance brief from current mini items."""
    paths = _paths()
    counts = build_ngo_relevance_brief(paths)
    console.print(f"NGO relevance brief items: {counts['brief_items']} from {counts['source_items']} mini items")
    console.print(f"Output: {paths.data_dir / 'mini' / 'current' / 'ngo_relevance_brief.md'}")


@smart_app.command("run")
def smart_run(
    config_set: str | None = typer.Option(None, "--config-set", help="Apply a named config set before running."),
    org_profile: Path | None = typer.Option(None, "--org-profile", help="Override config/org_profile.yaml for this run."),
    scoring_rules: Path | None = typer.Option(None, "--scoring-rules", help="Override config/scoring_rules.yaml for this run."),
    source_config: Path | None = typer.Option(None, "--source-config", help="Override config/source_config.yaml for this run."),
    allowlist: Path | None = typer.Option(None, "--allowlist", help="Override config/allowlist_domains.txt for this run."),
    brands: Path | None = typer.Option(None, "--brands", help="Override local_context/org/brands_used.txt for this run."),
    domains: Path | None = typer.Option(None, "--domains", help="Override local_context/org/domains.txt for this run."),
) -> None:
    """Run smart mode: normalize, score, and generate agent context."""
    paths = _paths()
    _prepare_config(
        paths,
        config_set=config_set,
        org_profile=org_profile,
        scoring_rules=scoring_rules,
        source_config=source_config,
        allowlist=allowlist,
        brands=brands,
        domains=domains,
    )
    indicator_count, vulnerability_count, scored_indicator_count, scored_vuln_count = _run_pipeline(paths)
    console.print(
        f"[green]Smart mode complete.[/] normalized={indicator_count} indicators/{vulnerability_count} vulnerabilities; "
        f"scored={scored_indicator_count} indicators/{scored_vuln_count} vulnerabilities"
    )


@config_app.command("list")
def config_list() -> None:
    """List named config sets."""
    paths = _paths()
    ensure_default_config_set(paths)
    table = Table(title="ThreatSucker Config Sets")
    table.add_column("Name")
    table.add_column("Active")
    table.add_column("Files")
    table.add_column("Path")
    for item in list_config_sets(paths):
        table.add_row(item.name, "yes" if item.active else "", f"{item.files_present}/{item.files_total}", str(item.path))
    console.print(table)


@config_app.command("save")
def config_save(
    name: str = typer.Argument(..., help="Name for the config set."),
    overwrite: bool = typer.Option(False, "--overwrite", help="Replace an existing config set."),
) -> None:
    """Save the current active config/local-context files as a named config set."""
    item = save_active_as_config_set(_paths(), name, overwrite=overwrite)
    console.print(f"[green]Saved config set:[/] {item.name} ({item.files_present}/{item.files_total} files)")


@config_app.command("apply")
def config_apply(name: str = typer.Argument(..., help="Name of the config set to apply.")) -> None:
    """Apply a named config set to the active project files."""
    item = apply_config_set(_paths(), name)
    console.print(f"[green]Applied config set:[/] {item.name}")


@show_app.command("top")
def show_top(limit: int = 20) -> None:
    """Print top scored indicators."""
    paths = _paths()
    items = read_jsonl(paths.scored_date_dir() / "relevant_indicators.jsonl", ScoredIndicator)
    items = sorted(items, key=lambda item: item.score, reverse=True)[:limit]
    table = Table(title="Top Scored Indicators")
    table.add_column("Priority")
    table.add_column("Score", justify="right")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Why")
    for item in items:
        table.add_row(item.priority, str(item.score), item.type, item.value, item.reasons[0] if item.reasons else "")
    console.print(table)


@app.command()
def explain(value: str = typer.Option(..., "--value", help="Indicator ID or value to explain.")) -> None:
    """Explain why one indicator received its score."""
    explain_indicator(_paths(), value)


@app.command("validate-config")
def validate_config() -> None:
    """Load config and local context, then print a compact summary."""
    paths = _paths()
    rules = load_scoring_rules(paths.config_dir / "scoring_rules.yaml")
    context = load_local_context(paths)
    console.print(f"Org: {context.org_profile.org_name} ({context.org_profile.country})")
    console.print(
        f"Domains: {len(context.domains)} | Brands: {len(context.brands_used)} | DNS rows: {len(context.dns_queries)} | "
        f"Hosts: {len(context.hosts)} | Browsers: {len(context.browsers)} | Services: {len(context.services)}"
    )
    console.print(f"Source weights: {', '.join(sorted(rules.get('source_weights', {}).keys()))}")


@app.command("overview")
def overview(json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON instead of Rich tables.")) -> None:
    """Show a correlated overview of devices, services, threats, and outputs."""
    data = build_overview(_paths())
    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return
    _print_overview(data)


@app.command("web")
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="Host/interface to bind."),
    port: int = typer.Option(8765, "--port", help="Port to listen on."),
    debug: bool = typer.Option(False, "--debug", help="Run Flask in debug mode."),
) -> None:
    """Start the optional Flask interface."""
    from .web import run_web

    console.print(f"Starting ThreatSucker web UI at http://{host}:{port}")
    run_web(_paths().project_root, host=host, port=port, debug=debug)


@app.command("import-dnscap")
def import_dnscap(
    path: Path = typer.Argument(..., help="DNScap dns.csv file or log root containing nested dns.csv files."),
    replace: bool = typer.Option(False, "--replace", help="Replace current DNS context instead of appending."),
) -> None:
    """Import DNScap dns.csv logs into local_context/dns/current/queries.csv."""
    paths = _paths()
    rows = read_dnscap_tree(path)
    target = paths.local_context_dir / "dns" / "current" / "queries.csv"
    existing = [] if replace or not target.exists() else read_dnscap_tree(target)
    combined = [*existing, *rows]
    headers = [
        "timestamp",
        "host",
        "queried_domain",
        "query_type",
        "source",
        "os",
        "interface",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
    ]
    write_csv(target, combined, headers=headers)
    console.print(f"Imported {len(rows)} DNScap DNS rows into {target}")


@app.command("import-enumeros")
def import_enumeros(
    path: Path = typer.Argument(..., help="Enumeros JSON output file."),
    replace: bool = typer.Option(False, "--replace", help="Replace imported asset CSV content instead of appending."),
) -> None:
    """Import Enumeros JSON into local asset context."""
    try:
        counts = import_enumeros_json(_paths(), path, append=not replace)
    except CollectorJsonError as exc:
        console.print(f"[red]Could not import Enumeros JSON:[/] {exc}")
        raise typer.Exit(1) from exc
    console.print(
        "Imported Enumeros: "
        + ", ".join(f"{key}={value}" for key, value in counts.items())
    )


@app.command("import-safesniff")
def import_safesniff(
    path: Path = typer.Argument(..., help="SafeSniff JSON output file."),
    replace: bool = typer.Option(False, "--replace", help="Replace imported asset CSV content instead of appending."),
) -> None:
    """Import SafeSniff JSON into local asset and exposed-port context."""
    try:
        counts = import_safesniff_json(_paths(), path, append=not replace)
    except CollectorJsonError as exc:
        console.print(f"[red]Could not import SafeSniff JSON:[/] {exc}")
        raise typer.Exit(1) from exc
    console.print(
        "Imported SafeSniff: "
        + ", ".join(f"{key}={value}" for key, value in counts.items())
    )


@app.command("highlight-dnscap")
def highlight_dnscap_command(
    dns_path: Path | None = typer.Option(None, "--dns", help="DNScap dns.csv/log root. Defaults to local_context DNS CSV."),
) -> None:
    """Highlight DNScap DNS queries that match current mini threat domains."""
    paths = _paths()
    highlights = highlight_current_mini(paths, dns_path)
    console.print(f"DNScap highlights: {len(highlights)}")
    console.print(f"Output: {paths.data_dir / 'mini' / 'current'}")


@app.command("filter-enumeros")
def filter_enumeros_command(
    paths: list[Path] = typer.Argument(..., help="Enumeros JSON file(s) or directories containing JSON files."),
) -> None:
    """Filter stored Enumeros JSON into AI-useful host findings."""
    project_paths = _paths()
    try:
        findings = filter_enumeros_documents(paths, project_paths.data_dir / "mini" / "current")
    except CollectorJsonError as exc:
        console.print(f"[red]Could not filter Enumeros JSON:[/] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"Enumeros findings: {len(findings)}")
    console.print(f"Output: {project_paths.data_dir / 'mini' / 'current'}")


@app.command("run-enumeros")
def run_enumeros_command(
    binary: Path = typer.Argument(..., help="Path to Enumeros binary for this host platform."),
    save_name: str | None = typer.Option(None, "--save-name", help="Optional filename for saved Enumeros JSON."),
) -> None:
    """Run Enumeros locally, save JSON, then filter it.

    Most workflows should prefer filter-enumeros on JSON collected from each platform.
    """
    paths = _paths()
    json_path = run_enumeros_binary(binary, paths, save_name)
    findings = filter_enumeros_documents([json_path], paths.data_dir / "mini" / "current")
    console.print(f"Saved Enumeros JSON: {json_path}")
    console.print(f"Enumeros findings: {len(findings)}")


def _print_overview(data: dict) -> None:
    summary = data["summary"]
    summary_table = Table(title="ThreatSucker Overview")
    summary_table.add_column("Metric")
    summary_table.add_column("Value", justify="right")
    for key, value in summary.items():
        summary_table.add_row(key.replace("_", " "), str(value))
    console.print(summary_table)

    device_table = Table(title="Devices And Local Context")
    device_table.add_column("Host")
    device_table.add_column("OS")
    device_table.add_column("Sources")
    device_table.add_column("Software")
    device_table.add_column("Browsers")
    device_table.add_column("Outdated")
    device_table.add_column("High-Risk Services")
    device_table.add_column("DNS Threat Matches")
    for device in data["devices"][:20]:
        high_services = ", ".join(f"{svc.get('service')}:{svc.get('port')}" for svc in device.get("high_risk_services", [])) or "-"
        device_table.add_row(
            device["host"],
            ", ".join(device.get("os", [])) or "-",
            ", ".join(device.get("sources", [])) or "-",
            str(device.get("software_count", 0)),
            str(device.get("browser_count", 0)),
            str(device.get("outdated_count", 0)),
            high_services,
            str(len(device.get("threat_dns_matches", []))),
        )
    console.print(device_table)

    updates_table = Table(title="Enumeros Update Status")
    updates_table.add_column("Host")
    updates_table.add_column("Subject")
    updates_table.add_column("Status")
    updates_table.add_column("Installed")
    updates_table.add_column("Latest")
    updates_table.add_column("Evidence")
    for row in data.get("update_status", [])[:20]:
        updates_table.add_row(
            str(row.get("host", "")),
            str(row.get("subject", "")),
            str(row.get("status", "")),
            str(row.get("installed") or "-"),
            str(row.get("latest") or "-"),
            str(row.get("evidence_path") or "-"),
        )
    console.print(updates_table)

    service_table = Table(title="Service Exposure Including SafeSniff")
    service_table.add_column("Host")
    service_table.add_column("Service")
    service_table.add_column("Port")
    service_table.add_column("Severity")
    service_table.add_column("Source")
    service_table.add_column("Correlation Use")
    for service in data["service_exposure"][:20]:
        service_table.add_row(
            str(service.get("host", "")),
            str(service.get("service", "")),
            str(service.get("port", "")),
            str(service.get("severity", "")) or "-",
            str(service.get("source", "")) or "-",
            str(service.get("correlation_use", "")),
        )
    console.print(service_table)

    threat_table = Table(title="Threat Context By Source")
    threat_table.add_column("Source")
    threat_table.add_column("Theme / Type")
    threat_table.add_column("Scope")
    threat_table.add_column("Count", justify="right")
    threat_table.add_column("Example")
    for row in data.get("threat_context", [])[:12]:
        example = row.get("examples", [{}])[0].get("value", "") if row.get("examples") else ""
        threat_table.add_row(row["source"], row["theme_or_type"], row["scope"], str(row["count"]), str(example)[:60])
    console.print(threat_table)

    vuln_table = Table(title="Browser / Software Vulnerability Context")
    vuln_table.add_column("Vulnerability")
    vuln_table.add_column("Source")
    vuln_table.add_column("Status")
    vuln_table.add_column("Matched local products")
    vuln_table.add_column("Signals")
    for row in data.get("vulnerability_context", [])[:12]:
        matched = ", ".join(f"{item.get('host')}:{item.get('product')} {item.get('version')}".strip() for item in row.get("matched_products", [])) or "-"
        signals = []
        if row.get("known_exploited"):
            signals.append("known exploited")
        if row.get("exploit_available"):
            signals.append("exploit")
        if row.get("cvss"):
            signals.append(f"CVSS {row['cvss']}")
        if row.get("is_demo"):
            signals.append("demo")
        vuln_table.add_row(str(row.get("vuln_id")), str(row.get("source")), str(row.get("match_status")), matched, ", ".join(signals) or "-")
    console.print(vuln_table)

    hints = Table(title="Correlation Hints")
    hints.add_column("Kind")
    hints.add_column("Summary")
    for hint in data["correlation_hints"]:
        hints.add_row(hint["kind"], hint["summary"])
    console.print(hints)
