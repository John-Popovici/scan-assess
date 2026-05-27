from __future__ import annotations


def product_names(software: list[dict]) -> set[str]:
    names: set[str] = set()
    for row in software:
        product = str(row.get("product", "")).strip().lower()
        if product:
            names.add(product)
    return names
