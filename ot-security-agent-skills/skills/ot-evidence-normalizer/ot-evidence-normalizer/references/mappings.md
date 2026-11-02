# Supported input mappings (version 0.1)

- `modbus-forensics`: `events` plus `write_candidates`; uses `file`, `frame`, `time_utc`, `src`, `dst`, `function`, `direction`, and `write_candidate`.
- `bacnet-forensics`: `sample_events` plus `state_change_candidates`; uses `capture`, `frame`, `utc`, `service`, `service_id`, and `kind`.
- `siemens-s7-forensics`: `captures[].events`; uses source `file`, `frame`, `time_utc`, `function_name`, and `state_change_candidate`.
- `iec104-forensics`: `captures[].events`; uses `file`, `frame`, `time_utc`, `asdu` and `control_command_candidate`.
- `ot-application-forensics`: `findings` are processed only when each finding carries its own valid, timezone-aware timestamp. Static configurations commonly lack timestamps, so they are skipped with warnings rather than falsely placed on the attack timeline.
- `generic-events`: accepts a JSON array or `{ "events": [...] }` with per-record timezone-aware `timestamp` or `time_utc` and an `action`; existing evidence locations are retained if they comply with the attack-chain schema.

## Output

- `attack-chain-events.json` follows `attack-chain-reconstruction/references/event-schema.md`, including `events`, `timestamp`, `action`, and evidence locators.
- `process-observations.json` follows `ot-process-analysis/references/input-schema.md`, including `case_id`, `observations`, operation labels and evidence stages.
- `normalization-summary.json` records original input JSON SHA-256, counts, skipped items, and limitations.

This tool does not directly parse raw PCAPs, syslog, vendor APIs, CSV, or proprietary binary exports. Upstream extraction is required. Operation categories are provisional. In particular, protocol acknowledgements and physical effects are **not** inferred.
