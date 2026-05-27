from ngo_intel.local_context.dns import read_dns_csv


def test_dnscap_dns_csv_is_normalized() -> None:
    rows = read_dns_csv("tests/fixtures/dnscap_dns_sample.csv")
    assert rows[0]["timestamp"] == "2026-05-02T10:31:22.123Z"
    assert rows[0]["host"] == "laptop-01"
    assert rows[0]["queried_domain"] == "invoice-bgl-secure.lu"
    assert rows[0]["query_type"] == "A"
    assert rows[0]["source"] == "dnscap"
    assert rows[0]["src_ip"] == "192.168.1.44"
