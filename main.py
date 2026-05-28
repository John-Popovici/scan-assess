from __future__ import annotations

import argparse
from pathlib import Path

from src.scan_assess import RunOptions, run_assessment


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
    parser.add_argument(
        "--prompt-profile",
        default=None,
        help="Prompt profile name from config/prompt_profiles.",
    )
    parser.add_argument(
        "--llm-profile",
        default=None,
        help="LLM profile name from config/llm_profiles.",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Scenario pack name from config/scenarios.",
    )
    parser.add_argument(
        "--prompt-dev-evidence",
        type=Path,
        help="JSON file containing editable validation evidence. When supplied, modules are not executed.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_assessment(
        RunOptions(
            demo=bool(args.demo),
            live=bool(args.live),
            prompt_profile=args.prompt_profile,
            llm_profile=args.llm_profile,
            scenario=args.scenario,
            prompt_dev_evidence=args.prompt_dev_evidence,
        )
    )


if __name__ == "__main__":
    main()
