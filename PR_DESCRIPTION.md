# PR Description

## Summary

This PR imports project-local versions of the requested non-quiz modules and wires them into scan-assess as runnable collectors/correlators:

- Enumeros: live local host/software/browser inventory.
- SafeSniff: conservative network target detection by default, with optional active scan mode.
- DNScap: DNS log importer with sample/imported provenance.
- ThreatSucker: explainable threat-intel filtering and correlation over scan-assess module outputs.

It also adds provenance-aware LLM prompting, explicit demo/live scan paths, and an operator-focused ThreatSucker config UI.

## Key Changes

- Added project-local module copies under `modules/` while leaving original source projects untouched.
- Added scan-assess runners for Enumeros, SafeSniff, DNScap, and ThreatSucker.
- Added multi-platform Rust binary handling for Enumeros, DNScap, and SafeSniff.
- Added provenance metadata across sample, imported, derived, target-detection-only, and live outputs.
- Added `python main.py --demo` for the bundled phishing-DNS demo scenario.
- Added `python main.py --live` for the official/default path.
- Kept module-specific runtime settings inside module-owned config files rather than top-level scan-assess CLI arguments.
- Added ThreatSucker config sets, CLI config commands, source toggles, visual scoring sliders, YAML validation, and source-file import.
- Added dependency updates for Flask, Typer/Rich, Pydantic, PyYAML, httpx, and dotenv.

## Prompt Changes

The scan-assess system/user prompts now instruct the LLM to:

- Treat module JSON files as the source of truth.
- Respect provenance metadata.
- Exclude sample/demo data from action items.
- Treat imported DNS logs as historical observations, not proof of compromise.
- Avoid describing SafeSniff target-detection-only output as a TCP service scan.
- Classify suspicious DNS domains by likely threat type, such as phishing, credential theft, brand impersonation, or invoice fraud.
- Name suspicious domains, identify the affected host when available, and recommend concrete follow-up steps.

## Demo And Live Behavior

- Demo phishing DNS lookups live under `modules/dnscap/imported_logs/`.
- Demo ThreatSucker feed items are present for local scenario testing.
- Official/live runs do not include demo ThreatSucker intel unless explicitly enabled in the ThreatSucker module config.
- ThreatSucker source normalization no longer falls back to fixtures unless a source mode explicitly contains `fixture`.

Useful commands:

```bash
uv run python main.py --help
uv run python main.py --demo
uv run python main.py --live
```

DNScap import windows and log roots are configured in `modules/dnscap/config/scan_assess_runtime.json`.
ThreatSucker config-set and demo-intel settings are configured in `modules/threatsucker/config/scan_assess_runtime.json`.

ThreatSucker UI:

```bash
cd modules/threatsucker/source
uv run threatsucker web --host 127.0.0.1 --port 8765
```

## Validation

Commands run during development:

```bash
python3 -m py_compile main.py src/scan_assess.py modules/threatsucker/runner.py modules/threatsucker/source/src/ngo_intel/normalize.py
uv run python main.py --help
uv run python -c 'from src.scan_assess import configure_run_mode, RunOptions; print("\n".join(configure_run_mode(RunOptions(demo=True))[0]))'
uv run python -c 'from src.scan_assess import configure_run_mode, RunOptions; print("\n".join(configure_run_mode(RunOptions(live=True))[0]))'
```

Demo run results:

- Latest verified full demo report: `reports/security_report_2026-05-23T10-08-48Z.md`
- Demo output directory: `outputs/2026-05-23T10-08-48Z/`
- The report identified the intended phishing/credential-theft DNS domains and correctly stated that SafeSniff did not perform a TCP service scan.

## Reviewer Notes

- `outputs/` and `reports/` are generated and ignored.
- Bundled demo data exists for repeatable local validation, but official scan-assess execution requires explicit opt-in through module config or `python main.py --demo`.
- SafeSniff defaults to target detection to avoid unsolicited network scanning.
- DNScap is integrated as a log importer rather than live packet capture.
