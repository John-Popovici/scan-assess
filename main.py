from __future__ import annotations

import argparse

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
    mode.add_argument(
        "--live",
        action="store_true",
        help="Run the normal official path. This is the default when --demo is not supplied.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_assessment(demo=bool(args.demo))


if __name__ == "__main__":
    main()
