---
name: ot-evidence-normalizer
description: Convert offline JSON forensic reports from Modbus, BACnet, S7comm, IEC-104, and structured OT observations into validated event and process-observation schemas for incident reconstruction. Use when combining industrial forensic evidence across analysis tools.
---

# OT Evidence Normalizer

Use this skill when a user has forensic JSON reports and needs standardized data for `attack-chain-reconstruction` or `ot-process-analysis`.

## Workflow

1. Obtain authorized, local forensic JSON reports from supported analyzers. Never connect to live controllers.
2. Run `python scripts/normalize_evidence.py <reports...> --output-dir <directory>` (use `python3` on Linux/macOS).
3. Examine `normalization-summary.json`, including skipped events and unsupported schemas.
4. Verify source capture packet references independently before drawing incident conclusions.
5. Use `attack-chain-events.json` as input to `attack-chain-reconstruction`; use `process-observations.json` as input to `ot-process-analysis`.
6. Do not infer malicious intent, command success, plant-specific scaling, or physical consequences solely from normalized records.

## Guardrails

- Treat mapping from Modbus register writes to `setpoint_write` as a provisional label, not a verified process mapping.
- Respect report sampling limits and timestamp requirements. Missing timezone-aware timestamps must not be guessed.
- The tool does not invent causal links between events or automatically supply plant-specific process context.
- JSON reports can contain passwords, addresses, and other secrets; handle privately.
- See `references/mappings.md` for supported inputs, coverage, and exclusions.
