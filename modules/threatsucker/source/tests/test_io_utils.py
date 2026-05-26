from ngo_intel.io_utils import read_csv_dicts, read_jsonl, stable_hash, write_csv, write_jsonl
from ngo_intel.models import NormalizedIndicator


def test_jsonl_and_csv_roundtrip(tmp_path) -> None:
    records = [
        NormalizedIndicator(
            indicator_id="one",
            source="misp_osint",
            type="domain",
            value="bad.example",
            normalized_value="bad.example",
            tags=["phishing"],
        )
    ]
    jsonl_path = tmp_path / "items.jsonl"
    csv_path = tmp_path / "items.csv"
    write_jsonl(jsonl_path, records)
    write_csv(csv_path, records)
    assert read_jsonl(jsonl_path, NormalizedIndicator)[0].value == "bad.example"
    csv_rows = read_csv_dicts(csv_path)
    assert csv_rows[0]["tags"] == '["phishing"]'
    assert stable_hash("same") == stable_hash("same")
