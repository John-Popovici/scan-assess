from __future__ import annotations

from ngo_intel.scoring import normalize_domain


def org_domains(domains: list[str]) -> set[str]:
    return {normalize_domain(domain) for domain in domains if domain.strip()}
