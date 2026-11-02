# OT Process Analysis — Agent Skill v0.1

Offline interpretation of industrial control observations. Designed to complement `pcap-forensics`, `modbus-forensics`, `bacnet-forensics`, `siemens-s7-forensics`, and `iec104-forensics`.

## Run on Windows 11 (PowerShell)

```powershell
cd .\ot-process-analysis
python -m unittest discover -s tests -v
python scripts\analyze_process.py examples\sample-observations.json --output process-report.json
```

Requires Python 3.9+; no third-party libraries. This is **not** a PCAP parser; convert verified protocol findings to the JSON schema in `references/input-schema.md` first.

## Scope

Labels potential industrial consequences without assuming the observed command succeeded. This initial version does not integrate with other skills automatically, infer plant-specific thresholds, interpret ladder logic, or verify actual physical impacts.
