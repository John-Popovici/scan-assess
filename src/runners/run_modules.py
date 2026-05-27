from __future__ import annotations

import importlib.util
import os
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


def _load_modules(modules_dir: Path) -> list[tuple[type[BaseRunner], Path]]:
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


def run_modules(modules_dir: Path, output_dir: Path) -> tuple[list[Path], list[str], list[str]]:
    generated_json_files: list[Path] = []
    info: list[str] = []
    errors: list[str] = []
    enabled_raw = os.environ.get("SCAN_ASSESS_ENABLED_MODULES", "").strip()
    disabled_raw = os.environ.get("SCAN_ASSESS_DISABLED_MODULES", "").strip()
    enabled_modules = {item.strip() for item in enabled_raw.split(",") if item.strip()}
    disabled_modules = {item.strip() for item in disabled_raw.split(",") if item.strip()}

    # Discover modules.
    runner_classes = _load_modules(modules_dir)

    # Iterate through each module
    for runner_class, module_dir in runner_classes:
        if enabled_modules and module_dir.name not in enabled_modules:
            info.append(f"{module_dir.name}: disabled by module selection.")
            continue
        if module_dir.name in disabled_modules:
            info.append(f"{module_dir.name}: disabled by module selection.")
            continue

        module_output_dir = output_dir / module_dir.name
        module_output_dir.mkdir(parents=True, exist_ok=True)

        try:
            runner_instance = runner_class()
            module_output_dir.mkdir(parents=True, exist_ok=True)
            success, module_files = runner_instance.run(module_output_dir, module_dir)
            if not success:
                errors.append(f"{module_dir.name}: Module returned failure.")
                continue
            generated_json_files.extend(
                [
                    file
                    for file in module_files
                    if file.suffix.lower() == ".json" and file.exists()
                ]
            )
            info.append(f"{module_dir.name}: {len(module_files)} files generated.")
        except Exception as exc:
            errors.append(f"{module_dir.name}: {exc}")

    return sorted(set(generated_json_files)), info, errors
