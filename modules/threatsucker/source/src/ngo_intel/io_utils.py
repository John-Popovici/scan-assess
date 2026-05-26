from __future__ import annotations

import csv
import hashlib
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel


def ensure_dir(path: str | Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _as_dict(record: Any) -> dict[str, Any]:
    if isinstance(record, BaseModel):
        return record.model_dump(mode="json")
    return dict(record)


def _json_ready(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return value


def write_jsonl(path: str | Path, records: Iterable[Any]) -> None:
    path = Path(path)
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            row = _as_dict(record)
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def read_jsonl(path: str | Path, model_cls: type[BaseModel] | None = None) -> list[Any]:
    path = Path(path)
    if not path.exists():
        return []
    records: list[Any] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            data = json.loads(line)
            records.append(model_cls.model_validate(data) if model_cls else data)
    return records


def write_csv(path: str | Path, records: Iterable[Any], headers: list[str] | None = None) -> None:
    path = Path(path)
    ensure_dir(path.parent)
    rows = [_as_dict(record) for record in records]
    fieldnames = headers or sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        if not fieldnames:
            return
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _json_ready(row.get(field, "")) for field in fieldnames})


def read_csv_dicts(path: str | Path) -> list[dict[str, str]]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def today_parts(value: date | datetime | None = None) -> tuple[str, str, str]:
    value = value or datetime.now()
    if isinstance(value, datetime):
        value = value.date()
    return f"{value.year:04d}", f"{value.month:02d}", f"{value.day:02d}"


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
