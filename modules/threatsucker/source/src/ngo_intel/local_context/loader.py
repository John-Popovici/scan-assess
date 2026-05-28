from __future__ import annotations

from pathlib import Path

from rich.console import Console

from ngo_intel.config import load_allowlist_domains, load_org_profile
from ngo_intel.io_utils import read_csv_dicts
from ngo_intel.local_context.dns import read_dns_csv, read_dnscap_tree
from ngo_intel.models import LocalContext
from ngo_intel.paths import ProjectPaths

console = Console()


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        console.print(f"[yellow]Optional local context file missing:[/] {path}")
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        console.print(f"[yellow]Optional local context file missing:[/] {path}")
        return []
    return read_csv_dicts(path)


def _read_dns_context(local: Path) -> list[dict[str, str]]:
    rows = read_dns_csv(local / "dns" / "current" / "queries.csv") if (local / "dns" / "current" / "queries.csv").exists() else []
    dnscap_current = local / "dns" / "current" / "dns.csv"
    if dnscap_current.exists():
        rows.extend(read_dns_csv(dnscap_current))
    dnscap_dir = local / "dns" / "dnscap"
    if dnscap_dir.exists():
        rows.extend(read_dnscap_tree(dnscap_dir))
    if not rows:
        console.print(f"[yellow]Optional local context file missing:[/] {local / 'dns' / 'current' / 'queries.csv'}")
    return rows


def load_local_context(paths: ProjectPaths) -> LocalContext:
    local = paths.local_context_dir
    org_profile_path = local / "org" / "org_profile.yaml"
    if not org_profile_path.exists():
        org_profile_path = paths.config_dir / "org_profile.yaml"
    return LocalContext(
        org_profile=load_org_profile(org_profile_path),
        domains=_read_lines(local / "org" / "domains.txt"),
        brands_used=_read_lines(local / "org" / "brands_used.txt"),
        dns_queries=_read_dns_context(local),
        hosts=_read_csv(local / "assets" / "hosts.csv"),
        software=_read_csv(local / "assets" / "software.csv"),
        browsers=_read_csv(local / "assets" / "browsers.csv"),
        services=_read_csv(local / "assets" / "services.csv"),
        exposed_ports=_read_csv(local / "assets" / "exposed_ports.csv"),
        allowlist_domains=load_allowlist_domains(paths.config_dir / "allowlist_domains.txt"),
    )
