# OT Evidence Normalizer

**Offline AI Agent Skill for normalizing industrial security findings into reusable incident evidence.**

## Overview

The normalizer bridges existing forensic JSON exports with two downstream skills: **Attack Chain Reconstruction** and **OT Process Analysis**. It is a conservative, read-only converter, not an incident detection system, vendor connector, or raw-PCAP parser.

## Supported inputs

JSON reports from `modbus-forensics`, `bacnet-forensics`, `siemens-s7-forensics`, and `iec104-forensics`. Limited structured application findings and generic JSON event arrays are also accepted; events without timezone-aware timestamps are skipped with warnings.

## Outputs

- `normalization-summary.json`: source JSON hashes, counts, warnings, limitations.
- `attack-chain-events.json`: event array compatible with the attack-chain schema.
- `process-observations.json`: operations compatible with the OT process schema.

**Important:** Inputs may contain only sampled events due to limits in upstream analyzers. No physical impact, authorization status, or causal link is inferred.

## Requirements

Python **3.9+**, standard library only. No third-party dependencies, no network access, and no TShark required. Intended for Windows 11, Linux, and macOS.

## Windows 11 (PowerShell)

From the repository root:

```powershell
cd .\ot-security-agent-skills\skills\ot-evidence-normalizer
python -m unittest discover -s tests -v
python scripts\normalize_evidence.py "C:\reports\modbus-report.json" "C:\reports\bacnet-report.json" --output-dir "C:\reports\normalized"
```

## Linux / macOS (Bash)

From the repository root:

```bash
cd ./ot-security-agent-skills/skills/ot-evidence-normalizer
python3 -m unittest discover -s tests -v
python3 scripts/normalize_evidence.py ~/reports/modbus-report.json ~/reports/bacnet-report.json --output-dir ~/reports/normalized
```

## Next steps

From the corresponding sibling skill directory (adjust paths to your installation):

```bash
python3 scripts/reconstruct_chain.py ../ot-evidence-normalizer/out/attack-chain-events.json --output timeline.json
python3 scripts/analyze_process.py ../ot-evidence-normalizer/out/process-observations.json --output process-report.json
```

The outputs are independent: execute the appropriate command from its own skill directory, with a correct path to the generated file.

## Documentation

`README.md` is for human operators; `SKILL.md` instructs compatible AI agents. Consult `references/mappings.md` for input field mappings and restrictions.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Known limitations

- Does **not** ingest raw PCAPs, live alerts, CSV, syslog, or vendor APIs.
- Does **not** automatically translate every report field; unsupported inputs produce warnings.
- Does **not** correlate causal relationships or prove actual industrial process impact.
- Only explicit, timezone-aware timestamps are used. Static evidence without times is not inserted into the timeline.
- Process-operation labels are provisional and require plant-specific validation.
- Original report fields are not copied wholesale, to limit accidental disclosure; input JSON and outputs may still contain sensitive identifiers. Treat them as sensitive and review before sharing.
- Normalization is based on supplied JSON reports, not independent validation of the underlying capture or log.

**Version 0.1.0 — Experimental.** Part of the OT Security Agent Skills initiative. Maintainer: Dr. Sulaiman Alhasawi (https://github.com/selmux).
