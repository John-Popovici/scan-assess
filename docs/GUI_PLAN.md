# GUI Workbench Plan

## Goal

Create a local NiceGUI operator workbench on top of the existing scan-assess CLI engine. The GUI should make demos, live runs, prompt selection, scenario packs, provenance, and evidence review visible without hiding the underlying YAML and JSON files.

## First Slice

- Prompt profiles in `config/prompt_profiles/`.
- Scenario packs in `config/scenarios/`.
- LLM profiles in `config/llm_profiles/`.
- CLI support for `--prompt-profile`, `--scenario`, and `--llm-profile`.
- Runtime module selection via GUI switches and `SCAN_ASSESS_ENABLED_MODULES`.
- Run manifests in each output directory.
- NiceGUI workbench at `src/gui_app.py`.
- GUI views for run controls, LLM-profile selection, prompt editing/validation, module detection/toggles, a first-class Reports tab, report-to-evidence links, module-folder Evidence browsing, highlighted evidence signals, and pretty JSON/JSONL/text evidence.
- A visible top-nav Prompt Developer view for scenario selection, system/user prompt editing, validation, per-module test choices, editable JSON evidence payloads, and false-positive checks.
- Prior generated reports/outputs imported into the ignored GUI worktree history so the browser can be exercised without running a scan.

## Next Slice

- Editable scenario builder in the GUI.
- Wire per-module Prompt Developer choices into richer evidence-payload generation, not just scenario-pack defaults.
- LLM profile editor with safe secret handling and endpoint health checks.
- Stronger finding-to-evidence linking from report text into specific JSON records or JSON paths.
- Side-by-side prompt comparison.
- Run comparison between previous outputs.
- Safer long-running task state with cancellation and clearer LLM server status.
