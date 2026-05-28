from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.table import Table

from .io_utils import read_jsonl
from .models import ScoredIndicator
from .paths import ProjectPaths

console = Console()


def explain_indicator(paths: ProjectPaths, value_or_id: str, date: datetime | None = None) -> ScoredIndicator | None:
    items = read_jsonl(paths.scored_date_dir(date) / "relevant_indicators.jsonl", ScoredIndicator)
    needle = value_or_id.lower()
    for item in items:
        if needle in {item.indicator_id.lower(), item.value.lower()} or needle in item.value.lower():
            table = Table(title="Indicator Explanation")
            table.add_column("Field")
            table.add_column("Value")
            table.add_row("indicator", item.value)
            table.add_row("score", str(item.score))
            table.add_row("priority", item.priority)
            table.add_row("reasons", "\n".join(item.reasons))
            table.add_row("matched local data", "\n".join(item.matched_local_data) or "none")
            table.add_row("recommended actions", "\n".join(item.recommended_actions))
            table.add_row("raw path", item.raw_path or "")
            console.print(table)
            return item
    console.print(f"[yellow]No scored indicator found for:[/] {value_or_id}")
    return None
