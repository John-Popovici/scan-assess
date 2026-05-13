from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import cast

from src.runners.base_runner import BaseRunner


def _load_runner(module_dir: Path) -> type | None:
    """Dynamically load the Runner class from the module's runner.py file."""
    runner_path = module_dir / "runner.py"
    if not runner_path.exists():
        return None

    spec = importlib.util.spec_from_file_location(
        f"runner_{module_dir.name}", runner_path
    )
    if spec is None or spec.loader is None:
        return None

    print(f"Loading runner: {module_dir.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    runner_class = getattr(module, "Runner", None)
    if runner_class is not None:
        return cast(type, runner_class)
    return None


def load_modules(modules_dir: Path) -> list[tuple[type[BaseRunner], Path]]:
    runner_classes: list[tuple[type[BaseRunner], Path]] = []

    # Discover a sorted list of module directories.
    discover_module_dirs: list[Path] = []
    if modules_dir.exists():
        discover_module_dirs = sorted(
            [path for path in modules_dir.iterdir() if path.is_dir()]
        )

    # Iterate through each module
    for module_dir in discover_module_dirs:
        runner_class = _load_runner(module_dir)
        if runner_class is not None:
            runner_classes.append((runner_class, module_dir))

    return runner_classes
