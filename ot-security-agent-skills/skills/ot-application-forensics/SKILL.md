---
name: ot-application-forensics
description: Offline forensic triage of Node-RED flows, Grafana dashboards and datasource exports, InfluxDB line-protocol dumps, and MariaDB SQL dumps/logs in ICS/OT and CTF investigations. Use for application artifacts, configuration exposure, query behavior, data sources, or IT-to-OT investigations. Never access live systems.
---

# OT Application Forensics

## Activation
Use this skill when supplied with exported Node-RED flow JSON, Grafana dashboard/datasource JSON, InfluxDB line-protocol or textual logs, MariaDB SQL dumps, and similar application artifacts. For raw PCAP, first invoke `pcap-forensics` and extract the application-layer evidence. For chronological multi-source analysis, hand normalized findings to `attack-chain-reconstruction`.

## Workflow
1. Work on local, read-only copies; record artifact name, size, and SHA-256.
2. Identify type and encoding based on content, not filename alone. If compressed or proprietary, use an appropriate offline extractor first; do not claim it was parsed when it was not.
3. Run `python scripts/analyze_apps.py artifact.json --output findings.json`. Multiple files accepted.
4. Review Node-RED function nodes, automation endpoints, and wired flow context; do not conclude a node executed from its presence alone.
5. Review Grafana panels, datasource references, and dashboard queries. Imported dashboards are not evidence that a query was executed.
6. Review InfluxDB measurements, timestamps, and retention context. Identify MariaDB statements, grants, table names where available; distinguish saved SQL from execution records.
7. Preserve file-specific references (JSON pointers, line numbers, hashes), correlate with PCAP/log observations, and explicitly separate observations from hypotheses.
8. Treat detected credentials as sensitive: output redacted values, never reproduce secrets unnecessarily. Pass proven flag candidates to `flag-validator`.

## Reporting
Provide artifact inventory, host/service references, authentication exposure (redacted), suspicious query/configuration indicators, associated evidence locations and hashes, uncertainty, and proposed defensive/CTF follow-up. Never fabricate a flag, successful login, SQL execution, or physical OT impact.

## Scope and safety
Offline static analysis only. Do not contact endpoints, attempt logins, fetch dashboards, execute flow code or SQL, or modify plant equipment. The included script performs heuristic triage, not complete service emulation, MariaDB protocol parsing, or PCAP analysis.

## Resources
- `scripts/analyze_apps.py`: standard-library offline JSON/text triage and evidence report.
- `references/artifacts.md`: supported export types, interpretation and evidence boundaries.
- `tests/test_analyze_apps.py`: portable regression tests.
