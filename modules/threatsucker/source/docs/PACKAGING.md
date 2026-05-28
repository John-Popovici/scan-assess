# Packaging And Deployment

ThreatSucker should be deployable as a small Python application with a default NGO profile.

## Current Development Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
threatsucker init
```

## Runtime Install Shape

The package exposes:

```text
threatsucker
ngo-intel
```

Both point to the same CLI.

The optional local web UI is started through the same command:

```bash
threatsucker web
```

Default profile:

```text
config/profiles/luxembourg_ngo.yaml
```

The default profile can be copied and changed. Future packaging work should make profile templates available even when installed outside a source checkout.

## Deployment Pattern

Recommended deployment directory:

```text
/srv/threatsucker/
  config/
  data/
  local_context/
```

Then run:

```bash
cd /srv/threatsucker
threatsucker init
threatsucker mini collect-live
threatsucker import-dnscap /path/to/dnscap/logs --replace
threatsucker filter-enumeros /path/to/enumeros-jsons
threatsucker mini ngo-brief
```

## Scheduled Use

For public feed updates:

```bash
threatsucker mini collect-live
```

For local evidence after a collection run:

```bash
threatsucker import-dnscap /path/to/dnscap/logs --replace
threatsucker filter-enumeros /path/to/enumeros-jsons
threatsucker mini ngo-brief
```

## Future Packaging TODOs

- Move default config/profile templates into package resources.
- Let `threatsucker init` copy templates from package resources when no source checkout exists.
- Add a Dockerfile for isolated scheduled runs.
- Add a documented output contract for `ngo_relevance_brief.json` and `deep_evidence.json`.
- Add deployment guidance for running the Flask UI behind local authentication if exposed beyond localhost.
