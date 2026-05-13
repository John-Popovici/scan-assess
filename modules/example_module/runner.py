"""Example runner implementation showing how to implement a BaseRunner."""

import json
from pathlib import Path

from src.runners.base_runner import BaseRunner


class Runner(BaseRunner):
    """Example runner that demonstrates the BaseRunner interface."""

    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        """Example implementation: generate a simple status JSON file."""

        # Generate example data
        example_data = {
            "module": "example",
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
