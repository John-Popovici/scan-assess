from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

IndicatorType = Literal["domain", "hostname", "url", "ip", "email", "hash", "cve", "text"]
Severity = Literal["low", "medium", "high", "critical"]
Priority = Literal["archive", "low", "medium", "high", "critical"]
Capacity = Literal["low", "medium", "high"]


class NormalizedIndicator(BaseModel):
    indicator_id: str
    source: str
    source_ref: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    type: IndicatorType
    value: str
    normalized_value: str
    category: str | None = None
    threat_type: list[str] = Field(default_factory=list)
    malware_family: str | None = None
    campaign: str | None = None
    actor: str | None = None
    tags: list[str] = Field(default_factory=list)
    confidence: int = 50
    severity: Severity = "medium"
    tlp: str | None = None
    description: str | None = None
    raw_path: str | None = None


class NormalizedVulnerability(BaseModel):
    vuln_id: str
    source: str
    published: datetime | None = None
    modified: datetime | None = None
    title: str
    description: str | None = None
    affected_products: list[dict[str, Any]] = Field(default_factory=list)
    cvss: float | None = None
    exploit_available: bool | None = None
    known_exploited: bool | None = None
    references: list[str] = Field(default_factory=list)
    raw_path: str | None = None


class ScoredIndicator(BaseModel):
    indicator_id: str
    score: int
    priority: Priority
    type: str
    value: str
    source: str
    reasons: list[str] = Field(default_factory=list)
    matched_local_data: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    raw_path: str | None = None


class ScoredVulnerability(BaseModel):
    vuln_id: str
    score: int
    priority: Priority
    title: str
    matched_assets: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    raw_path: str | None = None


class RiskItem(BaseModel):
    risk_id: str
    title: str
    risk_type: str
    priority: Literal["low", "medium", "high", "critical"]
    score: int
    why_relevant: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    agent_summary: str


class OrgProfile(BaseModel):
    org_name: str
    country: str
    languages: list[str]
    sector: str
    handles_sensitive_data: bool
    handles_donor_data: bool
    has_public_donation_page: bool
    uses_cloud_email: bool
    likely_targets: list[str]
    technical_capacity: Capacity


class MiniProfile(BaseModel):
    profile_id: str
    name: str
    description: str | None = None
    theme_rules: list[dict[str, Any]] = Field(default_factory=list)
    country_terms: list[str] = Field(default_factory=list)
    neighbouring_country_terms: list[str] = Field(default_factory=list)
    sector_terms: list[str] = Field(default_factory=list)
    brand_terms: list[str] = Field(default_factory=list)
    threat_focus: list[str] = Field(default_factory=list)
    high_impact_indicator_types: list[str] = Field(default_factory=list)
    include_sources: list[str] = Field(default_factory=list)
    output_limit: int = 50


class LocalContext(BaseModel):
    org_profile: OrgProfile
    domains: list[str] = Field(default_factory=list)
    brands_used: list[str] = Field(default_factory=list)
    dns_queries: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    software: list[dict[str, Any]] = Field(default_factory=list)
    browsers: list[dict[str, Any]] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    exposed_ports: list[dict[str, Any]] = Field(default_factory=list)
    allowlist_domains: list[str] = Field(default_factory=list)
