from __future__ import annotations

from pathlib import Path

from ngo_intel.io_utils import read_csv_dicts


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    return value


def queried_domains(rows: list[dict]) -> set[str]:
    return {normalize_domain(str(row.get("queried_domain", ""))) for row in rows if row.get("queried_domain")}


def normalize_dns_row(row: dict) -> dict[str, str]:
    """Normalize either ngo-intel DNS rows or DNScap dns.csv rows.

    DNScap writes: ts,host,os,interface,src_ip,dst_ip,src_port,dst_port,proto,qname,qtype.
    ngo-intel scoring expects: timestamp,host,queried_domain,query_type.
    We keep extra DNScap fields because they are useful evidence in explanations.
    """
    if "qname" in row:
        normalized = {
            "timestamp": str(row.get("ts", "")),
            "host": str(row.get("host", "")),
            "queried_domain": normalize_domain(str(row.get("qname", ""))),
            "query_type": str(row.get("qtype", "")),
            "source": "dnscap",
        }
        for field in ["os", "interface", "src_ip", "dst_ip", "src_port", "dst_port", "proto"]:
            if row.get(field) not in (None, ""):
                normalized[field] = str(row.get(field))
        return normalized
    return {
        **{str(key): str(value) for key, value in row.items()},
        "timestamp": str(row.get("timestamp", row.get("ts", ""))),
        "host": str(row.get("host", "")),
        "queried_domain": normalize_domain(str(row.get("queried_domain", row.get("qname", "")))),
        "query_type": str(row.get("query_type", row.get("qtype", ""))),
    }


def read_dns_csv(path: str | Path) -> list[dict[str, str]]:
    return [normalize_dns_row(row) for row in read_csv_dicts(path)]


def read_dnscap_tree(path: str | Path) -> list[dict[str, str]]:
    root = Path(path)
    if root.is_file():
        return read_dns_csv(root)
    rows: list[dict[str, str]] = []
    for dns_csv in sorted(root.glob("**/dns.csv")):
        rows.extend(read_dns_csv(dns_csv))
    return rows
