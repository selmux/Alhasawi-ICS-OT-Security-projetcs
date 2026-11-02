# Event input schema (v1)

Supply a JSON array of objects, or `{ "events": [...] }`. Each event must contain:

- `timestamp`: ISO 8601 with explicit timezone (e.g. `2026-09-08T02:17:00Z`) or Unix epoch numeric UTC.
- `action`: short neutral description of exactly what was observed.
- `evidence`: nonempty array of objects, each with `source` (original filename) and `frame`, `line`, `record`, or `detail` locator.

Optional event fields:

- `id`: unique stable ID (recommended for cross-file links).
- `source_ip`, `destination_ip`, `protocol`: directly observed endpoints/protocol.
- `stage`: one of `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `inhibit_response_function`, `impair_process_control`, `impact`, `other`.
- `confidence`: `observed` (default), `inferred`, or `hypothesis`.
- `related_to`: list of preceding event IDs where the analyst has evidence for a relationship.
- `rationale`: explanation of *why* a particular link is justified.
- `details`: protocol fields, raw bytes, account, rule IDs, or other technical context.

The program validates required evidence locations, sorts times in UTC, calculates SHA-256 hashes of all supplied JSON files, and produces `asserted_links` only from explicit `related_to` fields. It does **not** verify that the underlying capture contains the claimed packets; perform that check with the upstream forensic skill.
