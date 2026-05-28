from __future__ import annotations

import argparse
import sys

from src.module_config import parse_set_arguments
from src.scan_assess import run_assessment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run scan-assess modules and generate a local LLM security report.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--demo",
        action="store_true",
        help="Run the bundled phishing-DNS demo scenario with demo ThreatSucker intel enabled.",
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        help="Set a module config value (e.g., --set dnscap.period=last_week).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose module logging.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        module_overrides = parse_set_arguments(args.set)
    except ValueError as exc:
        print(f"Argument error: {exc}", file=sys.stderr)
        sys.exit(2)
    run_assessment(
        demo=bool(args.demo),
        verbose=bool(args.verbose),
        module_overrides=module_overrides,
    )


if __name__ == "__main__":
    main()
