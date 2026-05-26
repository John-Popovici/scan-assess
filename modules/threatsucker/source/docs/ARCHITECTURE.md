# ThreatSucker Architecture

ThreatSucker is organized around a small default core plus optional context extensions.

## Core Idea

The default installed profile is `luxembourg_ngo`. It builds a compact AI context pack for small Luxembourgish NGOs, but the profile is just YAML and can be replaced.

The project keeps three layers separate:

- Raw and normalized source evidence.
- Deep evidence for drill-down and traceability.
- Compact human and machine reports that reference deep evidence IDs.

## Mini Core

Mini mode is the default MVP path. It does not score items. It:

1. Normalizes available raw/live source data.
2. Applies a selected profile.
3. Writes a compact AI context pack.
4. Builds a relevance brief and `deep_evidence.json`.

Important outputs:

- `data/mini/current/ai_context.md`
- `data/mini/current/ai_context.json`
- `data/mini/current/ngo_relevance_brief.md`
- `data/mini/current/ngo_relevance_brief.json`
- `data/mini/current/deep_evidence.json`

## Deep Evidence

`deep_evidence.json` is the drill-down layer. It keeps structured records with stable IDs:

- `threat:*` for threat feed items.
- `vuln:*` for vulnerability records.
- `inventory:*` for local browser, OS, and software observations.
- `dns:*` for local DNS matches.

Reports stay small and reference these IDs.

## Optional Context Extensions

Extensions should add local context without changing mini mode into a large monolith.

Current extensions:

- DNScap DNS matching.
- Enumeros stored JSON filtering.
- SafeSniff stored JSON import.

Planned extension:

- Quiz or scan-assess JSON context.

The quiz extension should produce its own structured findings and then feed into the same report/deep-evidence pattern.

## Smart Mode

Smart mode still exists for explicit scoring experiments. It should remain separate from mini mode.

Mini answers:

> What useful context should the AI receive?

Smart answers:

> What should be prioritized after applying scoring rules?
