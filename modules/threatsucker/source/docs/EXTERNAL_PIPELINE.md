# Calling ThreatSucker From External Software

External software can call ThreatSucker either through the CLI or through a small Python API.

## CLI

Default NGO mini pack:

```bash
threatsucker mini run
threatsucker mini ngo-brief
```

Live public collection plus pack rebuild:

```bash
threatsucker mini collect-live
```

Local evidence:

```bash
threatsucker highlight-dnscap --dns /path/to/dns.csv
threatsucker filter-enumeros /path/to/enumeros.json
threatsucker import-safesniff /path/to/safesniff.json
```

## Python API

Use `ngo_intel.pipeline` when another program wants structured return values:

```python
from ngo_intel.pipeline import build_mini_pack, collect_live_and_build_pack

result = build_mini_pack(project_root="/srv/threatsucker")
print(result["relevance_brief_json"])
print(result["deep_evidence_json"])
```

Collect live public sources first:

```python
from ngo_intel.pipeline import collect_live_and_build_pack

result = collect_live_and_build_pack("/srv/threatsucker")
```

Get a correlated operator/AI overview:

```python
from ngo_intel.pipeline import build_pipeline_overview

overview = build_pipeline_overview("/srv/threatsucker")
print(overview["summary"])
print(overview["service_exposure"])
```

Import local collector evidence:

```python
from ngo_intel.pipeline import import_local_evidence

result = import_local_evidence(
    "/srv/threatsucker",
    dnscap_path="/tmp/dns.csv",
    enumeros_json="/tmp/enumeros-windows.json",
)
```

## Recommended Consumption Pattern

For a chatbot or downstream AI:

1. Read `data/mini/current/ngo_relevance_brief.json`.
2. Use `deep_evidence_path` to load `deep_evidence.json`.
3. Call `threatsucker overview --json` or `build_pipeline_overview()` for device/service/DNS correlation.
4. Follow `deep_evidence_ids` or `report_references` for drill-down.
5. Treat local DNS, SafeSniff service exposure, and inventory records as evidence, not conclusions.
