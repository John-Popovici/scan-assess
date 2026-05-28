from __future__ import annotations

import json
import re
import socket
import tempfile
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener


DEFAULT_CONFIG = {
    "enabled": True,
    "target_url": "https://eastlondonaudio.com",
    "max_pages": 10,
    "crawl_delay_seconds": 0.25,
    "request_timeout_seconds": 10,
    "check_security_headers": True,
    "check_cookie_flags": True,
    "crawl_same_site": True,
    "check_interesting_paths": True,
    "check_versions": True,
}

USER_AGENT = "Mozilla/5.0 (compatible; ScanAssessSiteChecker/1.0; owner-authorized)"
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]
INTERESTING_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
    "X-Cache",
    "CF-Ray",
    "Report-To",
    "NEL",
]
INTERESTING_PATHS = {
    "/robots.txt": "Robots file exposed",
    "/sitemap.xml": "Sitemap exposed",
    "/.well-known/security.txt": "Security contact file",
    "/security.txt": "Security contact file",
    "/.git/HEAD": "Exposed Git metadata",
    "/.env": "Potential environment file exposure",
    "/phpinfo.php": "Potential PHP info exposure",
    "/server-status": "Potential Apache server-status exposure",
    "/wp-login.php": "WordPress login page",
    "/wp-admin/": "WordPress admin area",
}
TECH_MARKERS = {
    "wp-content": "WordPress",
    "wordpress": "WordPress",
    "wp-json": "WordPress REST API",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "shopify": "Shopify",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "cloudflare": "Cloudflare",
    "nginx": "Nginx",
    "apache": "Apache",
    "__next": "Next.js",
}
VERSION_PATTERNS = {
    "jQuery": [re.compile(r"jquery[-.]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js", re.I)],
    "Bootstrap": [re.compile(r"bootstrap[-.]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.(?:css|js)", re.I)],
    "WordPress": [
        re.compile(r'generator["\']?\s+content=["\']WordPress\s+([0-9]+(?:\.[0-9]+)+)', re.I),
        re.compile(r"wp-includes/js/wp-emoji-release(?:\.min)?\.js\?ver=([0-9]+(?:\.[0-9]+)+)", re.I),
    ],
}
STALE_MAJOR_RULES = {
    "jQuery": {
        "1": "jQuery 1.x is legacy and commonly associated with old frontend stacks.",
        "2": "jQuery 2.x is legacy and should be reviewed.",
    },
    "Bootstrap": {"3": "Bootstrap 3.x is legacy."},
    "WordPress": {
        "4": "WordPress 4.x is very old.",
        "5": "WordPress 5.x should be checked against current maintenance status.",
    },
}
DEFAULT_VERSION_POLICY = {
    "schema_version": 1,
    "minimum_versions": {
        "jQuery": {
            "minimum_supported": "3.0.0",
            "severity": "medium",
            "rationale": "jQuery versions below 3.x are treated as legacy and should be reviewed.",
        },
        "Bootstrap": {
            "minimum_supported": "4.0.0",
            "severity": "medium",
            "rationale": "Bootstrap versions below 4.x are treated as legacy and should be reviewed.",
        },
        "WordPress": {
            "minimum_supported": "6.0.0",
            "severity": "medium",
            "rationale": "WordPress versions below 6.x should be checked against current vendor maintenance status.",
        },
    },
    "stale_major_versions": STALE_MAJOR_RULES,
    "notes": [
        "Minimum versions are operator-maintained policy baselines, not live vulnerability intelligence.",
        "Update this file when the organisation changes its accepted support baseline.",
    ],
}
LOGIN_TOKENS = {"login", "log in", "sign in", "signin", "account", "admin", "portal", "dashboard"}
SKIP_TOKENS = {"logout", "signout", "delete", "remove", "checkout", "cart", "basket"}
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class Component:
    name: str
    version: str | None
    source: str
    evidence: str
    confidence: str = "medium"


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.resources: list[str] = []
        self.form_count = 0
        self.meta: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "a" and values.get("href"):
            self.links.append(values["href"])
        if tag.lower() in {"script", "img"} and values.get("src"):
            self.resources.append(values["src"])
        if tag.lower() == "link" and values.get("href"):
            self.resources.append(values["href"])
        if tag.lower() == "form":
            self.form_count += 1
        if tag.lower() == "meta":
            self.meta.append((values.get("name", ""), values.get("content", "")))


def load_config(config_path: Path) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if config_path.exists():
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("SiteChecker config must be a JSON object.")
        config.update(raw)
    policy_path = config_path.parent / "version_policy.json"
    if "version_policy" not in config:
        config["version_policy"] = load_version_policy(policy_path)
    return config


def load_version_policy(policy_path: Path) -> dict[str, Any]:
    policy = json.loads(json.dumps(DEFAULT_VERSION_POLICY))
    if policy_path.exists():
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("SiteChecker version policy must be a JSON object.")
        policy.update(raw)
    return policy


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    messages: list[str] = []
    warnings: list[str] = []
    target = str(config.get("target_url") or "").strip()
    parsed = urlparse(normalize_url(target) or "")
    if not target:
        messages.append("target_url is required.")
    elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
        messages.append("target_url must be a valid HTTP or HTTPS URL.")
    if parsed.scheme == "http":
        warnings.append("Target uses HTTP. Use HTTPS unless intentionally checking plain HTTP.")
    for key in ["max_pages", "request_timeout_seconds"]:
        try:
            value = int(config.get(key, 0))
        except (TypeError, ValueError):
            messages.append(f"{key} must be an integer.")
            continue
        if value < 1:
            messages.append(f"{key} must be at least 1.")
    try:
        delay = float(config.get("crawl_delay_seconds", 0))
        if delay < 0:
            messages.append("crawl_delay_seconds cannot be negative.")
    except (TypeError, ValueError):
        messages.append("crawl_delay_seconds must be numeric.")
    if "enabled" in config and not isinstance(config["enabled"], bool):
        messages.append("enabled must be true or false.")
    for key in [
        "check_security_headers",
        "check_cookie_flags",
        "crawl_same_site",
        "check_interesting_paths",
        "check_versions",
    ]:
        if key in config and not isinstance(config[key], bool):
            messages.append(f"{key} must be true or false.")
    policy_validation = validate_version_policy(config.get("version_policy", DEFAULT_VERSION_POLICY))
    messages.extend(policy_validation["messages"])
    warnings.extend(policy_validation["warnings"])
    return {
        "valid": not messages,
        "messages": messages,
        "warnings": warnings,
        "summary": "Config is valid." if not messages else f"{len(messages)} issue(s) found.",
    }


def validate_version_policy(policy: Any) -> dict[str, Any]:
    messages: list[str] = []
    warnings: list[str] = []
    if not isinstance(policy, dict):
        return {"valid": False, "messages": ["version_policy must be a JSON object."], "warnings": []}
    minimum_versions = policy.get("minimum_versions", {})
    if not isinstance(minimum_versions, dict):
        messages.append("version_policy.minimum_versions must be an object.")
    else:
        for component, rule in minimum_versions.items():
            if not isinstance(rule, dict):
                messages.append(f"version_policy.minimum_versions.{component} must be an object.")
                continue
            minimum_supported = str(rule.get("minimum_supported", "")).strip()
            if not minimum_supported:
                messages.append(f"version_policy.minimum_versions.{component}.minimum_supported is required.")
            elif not parse_version(minimum_supported):
                messages.append(f"version_policy.minimum_versions.{component}.minimum_supported must contain a numeric version.")
            severity = str(rule.get("severity", "medium"))
            if severity not in {"info", "low", "medium", "high", "critical"}:
                messages.append(f"version_policy.minimum_versions.{component}.severity must be info, low, medium, high, or critical.")
    stale_major_versions = policy.get("stale_major_versions", {})
    if not isinstance(stale_major_versions, dict):
        messages.append("version_policy.stale_major_versions must be an object.")
    elif not stale_major_versions:
        warnings.append("version_policy.stale_major_versions is empty; only exact minimum-version checks will run.")
    return {"valid": not messages, "messages": messages, "warnings": warnings}


def scan_site(config: dict[str, Any]) -> dict[str, Any]:
    validation = validate_config(config)
    target = str(config.get("target_url") or "")
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report: dict[str, Any] = {
        "tool": "sitechecker",
        "mode": "owner_authorized_website_exposure_check",
        "target_url": target,
        "normalized_url": normalize_url(target),
        "provenance": {
            "data_origin": "live" if config.get("enabled", True) else "disabled",
            "collection_method": "single_website_http_observation",
            "live_collection": bool(config.get("enabled", True)),
            "active_network_scan": bool(config.get("enabled", True)),
            "sample_data": False,
            "scope_note": "Designed for owner-authorized checks against a single website.",
        },
        "config": {
            "max_pages": int(config.get("max_pages", DEFAULT_CONFIG["max_pages"])),
            "crawl_delay_seconds": float(config.get("crawl_delay_seconds", DEFAULT_CONFIG["crawl_delay_seconds"])),
            "request_timeout_seconds": int(config.get("request_timeout_seconds", DEFAULT_CONFIG["request_timeout_seconds"])),
            "check_security_headers": bool(config.get("check_security_headers", True)),
            "check_cookie_flags": bool(config.get("check_cookie_flags", True)),
            "crawl_same_site": bool(config.get("crawl_same_site", True)),
            "check_interesting_paths": bool(config.get("check_interesting_paths", True)),
            "check_versions": bool(config.get("check_versions", True)),
            "version_policy": summarize_version_policy(config.get("version_policy", DEFAULT_VERSION_POLICY)),
        },
        "started_at_utc": started,
        "validation": validation,
        "reachable": False,
        "findings": [],
        "summary": {},
    }
    if not config.get("enabled", True):
        report["summary"] = {"status": "disabled", "risk_level": "Not run", "risk_score": 0}
        return report
    if not validation["valid"]:
        report["summary"] = {"status": "invalid_config", "risk_level": "Unknown", "risk_score": 0}
        return report

    opener = build_opener()
    normalized = report["normalized_url"]
    assert isinstance(normalized, str)
    try:
        first = fetch(opener, normalized, int(config["request_timeout_seconds"]))
    except Exception as exc:
        report["summary"] = {"status": "unreachable", "error": str(exc), "risk_level": "Unknown", "risk_score": 0}
        return report

    report.update(
        {
            "reachable": True,
            "final_url": first["url"],
            "status_code": first["status_code"],
            "https": first["url"].startswith("https://"),
            "interesting_headers": {
                header: get_header(first["headers"], header)
                for header in INTERESTING_HEADERS
                if get_header(first["headers"], header)
            },
        }
    )
    if bool(config.get("check_security_headers", True)):
        report["security_headers"] = {header: header.lower() in first["headers_lc"] for header in SECURITY_HEADERS}
        missing_headers = [header for header, present in report["security_headers"].items() if not present]
        report["missing_headers"] = missing_headers
        for header in missing_headers:
            report["findings"].append(asdict(missing_header_finding(header, first["url"])))
    else:
        report["security_headers"] = {}
        report["missing_headers"] = []
    if not report["https"]:
        report["findings"].append(
            asdict(
                Finding(
                    id="site_not_https",
                    title="Website did not resolve to HTTPS",
                    severity="high",
                    evidence={"url": first["url"]},
                    recommendation="Redirect all public traffic to HTTPS and enable HSTS once deployment is stable.",
                )
            )
        )

    if bool(config.get("check_cookie_flags", True)):
        cookie_issues = check_cookie_flags(first.get("set_cookie", []), first["url"])
        report["cookie_issues"] = cookie_issues
        report["findings"].extend(asdict(cookie_finding(issue)) for issue in cookie_issues)
    else:
        report["cookie_issues"] = []

    if bool(config.get("check_interesting_paths", True)):
        exposed, path_findings = check_interesting_paths(opener, first["url"], int(config["request_timeout_seconds"]))
        report["exposed_paths"] = exposed
        report["findings"].extend(asdict(item) for item in path_findings)
    else:
        report["exposed_paths"] = []

    if bool(config.get("crawl_same_site", True)):
        crawl = crawl_pages(
            opener=opener,
            start_url=first["url"],
            max_pages=int(config["max_pages"]),
            delay=float(config["crawl_delay_seconds"]),
            timeout=int(config["request_timeout_seconds"]),
            check_versions=bool(config.get("check_versions", True)),
            version_policy=config.get("version_policy", DEFAULT_VERSION_POLICY),
        )
        report.update(crawl)
        report["findings"].extend(crawl["component_findings"])
        report.pop("component_findings", None)
    else:
        report.update(
            {
                "detected_tech": sorted(detect_tech(first["headers"], first["body"])),
                "observed_components": [],
                "emails_found": [],
                "exposure_points": {
                    "login_pages": [],
                    "forms_count": 0,
                    "internal_pages_scanned": 1,
                    "subdomains": [],
                },
            }
        )
    score, level = risk_score(report["findings"], report.get("exposure_points", {}))
    report["summary"] = {
        "status": "completed",
        "risk_score": score,
        "risk_level": level,
        "findings_total": len(report["findings"]),
        "findings_by_severity": severity_counts(report["findings"]),
        "assessment_note": "Header, banner, path, and HTML-marker checks are exposure evidence and should be manually verified before claiming exploitability.",
    }
    return report


def normalize_url(url: str) -> str | None:
    url = str(url or "").strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def fetch(opener: Any, url: str, timeout: int) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = opener.open(request, timeout=timeout)
        body = response.read(512_000)
        status = response.status
        final_url = response.geturl()
        headers = dict(response.headers.items())
        set_cookie = response.headers.get_all("Set-Cookie") or []
    except HTTPError as exc:
        body = exc.read(128_000)
        status = exc.code
        final_url = exc.geturl()
        headers = dict(exc.headers.items())
        set_cookie = exc.headers.get_all("Set-Cookie") or []
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc
    return {
        "url": final_url,
        "status_code": status,
        "headers": headers,
        "headers_lc": {key.lower(): value for key, value in headers.items()},
        "set_cookie": set_cookie,
        "content_type": get_header(headers, "Content-Type"),
        "body": body.decode("utf-8", errors="replace"),
    }


def get_header(headers: dict[str, str], name: str) -> str:
    return str(headers.get(name) or headers.get(name.lower()) or headers.get(name.title()) or "")


def missing_header_finding(header: str, url: str) -> Finding:
    severity = "medium" if header in {"Strict-Transport-Security", "Content-Security-Policy"} else "low"
    return Finding(
        id=f"missing_{header.lower().replace('-', '_')}",
        title=f"Missing {header} header",
        severity=severity,
        evidence={"url": url, "missing_header": header},
        recommendation=f"Review whether {header} should be set for this site.",
        notes=["Missing headers are hardening issues, not proof of exploitability by themselves."],
    )


def check_cookie_flags(cookies: list[str], url: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip() or "unnamed"
        lowered = cookie.lower()
        missing = []
        for flag in ["secure", "httponly", "samesite"]:
            if flag not in lowered:
                missing.append(flag)
        if missing:
            issues.append({"url": url, "cookie": name, "missing_flags": missing})
    return issues


def cookie_finding(issue: dict[str, Any]) -> Finding:
    return Finding(
        id="cookie_missing_security_flags",
        title=f"Cookie {issue.get('cookie')} is missing security flags",
        severity="medium" if "secure" in issue.get("missing_flags", []) else "low",
        evidence=issue,
        recommendation="Set Secure, HttpOnly, and SameSite on session or sensitive cookies where compatible.",
        notes=["Cookie flags reduce session theft and cross-site request risk but must be reviewed against application needs."],
    )


def check_interesting_paths(opener: Any, base_url: str, timeout: int) -> tuple[list[dict[str, Any]], list[Finding]]:
    exposed: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for path, description in INTERESTING_PATHS.items():
        url = urljoin(base_url, path)
        try:
            response = fetch(opener, url, timeout)
        except Exception:
            continue
        record = {
            "path": path,
            "url": url,
            "description": description,
            "status_code": response["status_code"],
            "content_type": get_header(response["headers"], "Content-Type"),
            "content_length": get_header(response["headers"], "Content-Length"),
        }
        if response["status_code"] in {200, 401, 403}:
            exposed.append(record)
        if path in {"/.git/HEAD", "/.env"} and response["status_code"] == 200:
            findings.append(
                Finding(
                    id="exposed_git_metadata" if path == "/.git/HEAD" else "exposed_env_file",
                    title="Exposed Git metadata" if path == "/.git/HEAD" else "Potential exposed environment file",
                    severity="high",
                    evidence=record,
                    recommendation="Block public access immediately and rotate any exposed secrets if contents were accessible.",
                    notes=["This checker records metadata only and does not dump sensitive file contents."],
                )
            )
        elif path in {"/phpinfo.php", "/server-status"} and response["status_code"] == 200:
            findings.append(
                Finding(
                    id=f"exposed_{path.strip('/').replace('.', '_').replace('-', '_')}",
                    title=description,
                    severity="high",
                    evidence=record,
                    recommendation="Restrict this diagnostic/status endpoint to trusted administrators or remove it.",
                )
            )
    return exposed, findings


def crawl_pages(
    opener: Any,
    start_url: str,
    max_pages: int,
    delay: float,
    timeout: int,
    check_versions: bool,
    version_policy: dict[str, Any],
) -> dict[str, Any]:
    queue: deque[str] = deque([start_url])
    visited: set[str] = set()
    base_host = host(start_url)
    tech: set[str] = set()
    emails: set[str] = set()
    login_pages: set[str] = set()
    subdomains: set[str] = set()
    form_count = 0
    components: list[dict[str, Any]] = []
    component_findings: list[dict[str, Any]] = []
    while queue and len(visited) < max_pages:
        current = queue.popleft()
        if current in visited or should_skip(current):
            continue
        visited.add(current)
        try:
            response = fetch(opener, current, timeout)
        except Exception:
            continue
        if "text/html" not in response["content_type"].lower():
            continue
        html = response["body"]
        parser = LinkParser()
        parser.feed(html)
        html_with_resources = html + "\n" + "\n".join(parser.resources)
        text = strip_tags_text(html)
        tech.update(detect_tech(response["headers"], html_with_resources))
        emails.update(match.group(0).lower() for match in EMAIL_RE.finditer(text))
        form_count += parser.form_count
        if any(token in current.lower() or token in text[:700].lower() for token in LOGIN_TOKENS):
            login_pages.add(current)
        if check_versions:
            for component in extract_components(response["headers"], html_with_resources):
                item = asdict(component)
                if item not in components:
                    components.append(item)
                finding = stale_component_finding(component, current, version_policy)
                if finding:
                    as_dict = asdict(finding)
                    if as_dict not in component_findings:
                        component_findings.append(as_dict)
        for href in parser.links:
            link = urljoin(response["url"], href)
            if should_skip(link) or not same_domain(start_url, link):
                continue
            link_host = host(link)
            if link_host and link_host != base_host:
                subdomains.add(link_host)
            if link not in visited and len(queue) < max_pages * 2:
                queue.append(link)
        if delay:
            time.sleep(delay)
    return {
        "detected_tech": sorted(tech),
        "observed_components": components,
        "emails_found": sorted(emails),
        "exposure_points": {
            "login_pages": sorted(login_pages),
            "forms_count": form_count,
            "internal_pages_scanned": len(visited),
            "subdomains": sorted(subdomains),
        },
        "component_findings": component_findings,
    }


def strip_tags_text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def detect_tech(headers: dict[str, str], html: str) -> list[str]:
    blob = (json.dumps(headers) + "\n" + html).lower()
    found = {label for marker, label in TECH_MARKERS.items() if marker in blob}
    server = get_header(headers, "Server").lower()
    if "nginx" in server:
        found.add("Nginx")
    if "apache" in server:
        found.add("Apache")
    powered = get_header(headers, "X-Powered-By").lower()
    if "php" in powered:
        found.add("PHP")
    return sorted(found)


def extract_components(headers: dict[str, str], html: str) -> list[Component]:
    blob = json.dumps(headers) + "\n" + html
    components: list[Component] = []
    for name, patterns in VERSION_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(blob)
            if match:
                components.append(Component(name=name, version=match.group(1), source="headers_or_html", evidence=match.group(0)[:160]))
                break
    return components


def stale_component_finding(component: Component, url: str, version_policy: dict[str, Any]) -> Finding | None:
    if not component.version:
        return None
    minimum_rule = version_policy.get("minimum_versions", {}).get(component.name, {})
    minimum_supported = str(minimum_rule.get("minimum_supported", "")).strip()
    if minimum_supported and compare_versions(component.version, minimum_supported) < 0:
        severity = str(minimum_rule.get("severity", "medium"))
        rationale = str(minimum_rule.get("rationale", "Observed version is below the configured minimum supported baseline."))
        return Finding(
            id=f"possibly_outdated_{component.name.lower().replace(' ', '_')}",
            title=f"Possibly stale component detected: {component.name} {component.version}",
            severity=severity,
            evidence={
                "url": url,
                "component": component.name,
                "observed_version": component.version,
                "minimum_supported": minimum_supported,
                "source": component.source,
                "comparison": "observed_version_below_configured_minimum",
            },
            recommendation="Verify the deployed component version against vendor support and patch policy, then upgrade or document supported backports.",
            notes=[rationale, "This is an operator-maintained baseline check, not live vulnerability intelligence."],
        )
    major = component.version.split(".", 1)[0]
    rule = version_policy.get("stale_major_versions", {}).get(component.name, {}).get(major)
    if not rule:
        return None
    return Finding(
        id=f"possibly_outdated_{component.name.lower().replace(' ', '_')}",
        title=f"Possibly outdated component detected: {component.name} {component.version}",
        severity="medium",
        evidence={"url": url, "component": component.name, "version": component.version, "source": component.source},
        recommendation="Verify the deployed component version and upgrade or confirm vendor-supported security backports.",
        notes=[rule, "This is a legacy-major heuristic, not confirmed exploitability."],
    )


def parse_version(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(version))
    return tuple(int(part) for part in parts)


def compare_versions(left: str, right: str) -> int:
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    max_len = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (max_len - len(left_parts))
    right_padded = right_parts + (0,) * (max_len - len(right_parts))
    if left_padded < right_padded:
        return -1
    if left_padded > right_padded:
        return 1
    return 0


def summarize_version_policy(policy: dict[str, Any]) -> dict[str, Any]:
    minimum_versions = policy.get("minimum_versions", {})
    stale_major_versions = policy.get("stale_major_versions", {})
    return {
        "minimum_versions": {
            component: rule.get("minimum_supported")
            for component, rule in minimum_versions.items()
            if isinstance(rule, dict)
        },
        "stale_major_versions": {
            component: sorted(str(major) for major in rules)
            for component, rules in stale_major_versions.items()
            if isinstance(rules, dict)
        },
    }


def host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def same_domain(base_url: str, target_url: str) -> bool:
    base = host(base_url)
    target = host(target_url)
    return bool(base and target and (target == base or target.endswith(f".{base}")))


def should_skip(url: str) -> bool:
    lowered = url.lower()
    parsed = urlparse(url)
    return parsed.scheme not in {"http", "https"} or any(token in lowered for token in SKIP_TOKENS)


def risk_score(findings: list[dict[str, Any]], exposure: dict[str, Any]) -> tuple[int, str]:
    weights = {"info": 0, "low": 1, "medium": 2, "high": 4, "critical": 6}
    score = sum(weights.get(str(item.get("severity", "info")), 0) for item in findings)
    if exposure.get("login_pages"):
        score += 1
    if int(exposure.get("forms_count") or 0) > 5:
        score += 1
    if score >= 10:
        return score, "High"
    if score >= 5:
        return score, "Medium"
    return score, "Low"


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def run_validation_suite() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "index.html").write_text(
            """<html><head><script src="/static/jquery-1.12.4.min.js"></script></head>
            <body><h1>Validation Site</h1><a href="/login">Login</a><form action="/contact"></form></body></html>""",
            encoding="utf-8",
        )
        (root / "login").write_text("<html><body><h1>Sign in</h1><form></form></body></html>", encoding="utf-8")
        (root / ".env").write_text("SECRET_KEY=validation-only", encoding="utf-8")
        server = _ValidationServer(root)
        try:
            server.start()
            result = scan_site(
                {
                    **DEFAULT_CONFIG,
                    "target_url": server.url,
                    "max_pages": 4,
                    "crawl_delay_seconds": 0,
                    "request_timeout_seconds": 3,
                }
            )
        finally:
            server.stop()
    findings = {item["id"]: item for item in result.get("findings", [])}
    cases = [
        _case("reachable", "Validation site is reachable.", bool(result.get("reachable")), "reachable=true", str(result.get("reachable"))),
        _case("missing_headers", "Missing security headers are reported.", "missing_content_security_policy" in findings, "CSP finding present", ", ".join(findings)),
        _case("exposed_env", "Exposed .env path is high severity.", findings.get("exposed_env_file", {}).get("severity") == "high", "high exposed_env_file", json.dumps(findings.get("exposed_env_file", {}))),
        _case("legacy_jquery", "Legacy jQuery version is detected.", "possibly_outdated_jquery" in findings, "possibly_outdated_jquery present", ", ".join(findings)),
        _case("login_surface", "Login page exposure is recorded.", bool(result.get("exposure_points", {}).get("login_pages")), "login page recorded", json.dumps(result.get("exposure_points", {}))),
    ]
    return {
        "status": "pass" if all(item["passed"] for item in cases) else "fail",
        "summary": {
            "total": len(cases),
            "passed": sum(1 for item in cases if item["passed"]),
            "failed": sum(1 for item in cases if not item["passed"]),
        },
        "cases": cases,
        "sample_result": result,
    }


def _case(name: str, description: str, passed: bool, expected: str, actual: str) -> dict[str, Any]:
    return {"name": name, "description": description, "passed": passed, "expected": expected, "actual": actual}


class _ValidationServer:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""

    def start(self) -> None:
        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, directory=str(self_root), **kwargs)

            def do_GET(self) -> None:
                if self.path in {"/", "/index.html"}:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write((self_root / "index.html").read_bytes())
                    return
                if self.path == "/login":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write((self_root / "login").read_bytes())
                    return
                if self.path == "/.env":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"SECRET_KEY=validation-only")
                    return
                super().do_GET()

            def log_message(self, format: str, *args: Any) -> None:
                return

        self_root = self.root
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{port}/"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=2)
