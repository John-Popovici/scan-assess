from ngo_intel.local_context.dnscap_highlight import highlight_dnscap
from ngo_intel.io_utils import write_jsonl


def test_dnscap_highlight_matches_mini_domain(tmp_path) -> None:
    dns = tmp_path / "dns.csv"
    dns.write_text(
        "ts,host,os,interface,src_ip,dst_ip,src_port,dst_port,proto,qname,qtype\n"
        "2026-05-10T10:00:00.000Z,laptop-01,windows,eth0,10.0.0.2,1.1.1.1,55555,53,udp,invoice-bgl-secure.lu,A\n",
        encoding="utf-8",
    )
    items = tmp_path / "threat_items.jsonl"
    write_jsonl(
        items,
        [
            {
                "item_id": "item-1",
                "title": "domain: invoice-bgl-secure.lu",
                "domain": "invoice-bgl-secure.lu",
                "source": "misp_osint",
                "threat_type": ["phishing"],
            }
        ],
    )
    highlights = highlight_dnscap(dns, items, tmp_path / "out")
    assert len(highlights) == 1
    assert highlights[0]["host"] == "laptop-01"
    assert highlights[0]["match_type"] == "exact"
    assert (tmp_path / "out" / "dnscap_highlights.csv").exists()
