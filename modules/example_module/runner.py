"""Example runner implementation showing how to implement a BaseRunner."""

import json
from pathlib import Path

from src.runners.base_runner import BaseRunner


class Runner(BaseRunner):
    """Example runner that demonstrates the BaseRunner interface."""

    def validation_options(self) -> dict:
        return {
            "conditions": {
                "off": "Off",
                "nominal": "Nominal telemetry",
            },
            "scopes": {"module_default": "Module default"},
            "default_condition": "nominal",
            "default_scope": "module_default",
            "supports_true_positive": False,
        }

    def generate_validation_evidence(self, condition: str = "nominal", **_: object) -> list[dict]:
        if condition == "off":
            return []
        return [
            {
                "filename": "example_module/example_output.json",
                "file_data": {
                    "module": "example_module",
                    "provenance": {"data_origin": "operator_supplied", "sample_data": False},
                    "status": "no actionable findings",
                },
            }
        ]

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        """Example implementation: generate a simple status JSON file."""

        # Generate example data
        example_data = {
            "module": "example",
            "provenance": {
                "data_origin": "sample",
                "collection_method": "example_runner",
                "live_collection": False,
                "sample_data": True,
                "note": "Demo module output for framework testing; do not treat as real security telemetry.",
            },
            "status": "success",
            "message": "This is an example runner implementation.",
            "output_location": str(output_dir),
            "module_location": str(module_dir),
            "files_generated": 1,
        }

        # Write to output file
        output_path = output_dir / "example_output.json"
        output_path.write_text(json.dumps(example_data, indent=2), encoding="utf-8")

        return True, [output_path]
