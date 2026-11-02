---
name: attack-chain-reconstruction
description: Reconstruct evidence-backed cybersecurity and ICS/OT attack timelines from structured events extracted from PCAPs, authentication logs, host artifacts, and industrial protocol reports. Use when correlating multiple sources, identifying pivots, describing attack stages, or explaining incident chronology without inventing causality.
---

# Attack Chain Reconstruction

## When to activate

Use this skill when the user provides multiple artifacts or asks for an attack timeline, lateral-movement path, initial-access sequence, IT-to-OT pivot, OT action chronology, or connections among forensic findings. Do not activate solely because the input is a PCAP: first use `pcap-forensics` or a protocol skill to extract evidence.

## Workflow

1. Inventory evidence sources; retain filenames, cryptographic hashes, packet/frame numbers, and log line references.
2. Use upstream forensic skills to extract events; normalize them into the `references/event-schema.md` JSON format. Do **not** fabricate evidence when raw sources are unavailable.
3. Use explicit UTC timestamps, converting from known timezones. Never guess an unknown timezone.
4. Set each event's `stage`, `confidence`, and `evidence`. Mark facts as `observed`; analytical conclusions as `inferred`; unverified ideas as `hypothesis`.
5. Add `related_to` **only** when there is a reasoned connection supported by evidence; do not equate timing with causation. Include the reasoning in an event's `rationale` field.
6. Run `python scripts/reconstruct_chain.py evidence.json --output chain.json --markdown chain.md`. Multiple input JSON files are supported.
7. Review the chronology, missing references, timestamp discrepancies, and competing explanations. Corroborate suspected writes with responses and telemetry where available.
8. Report events, supported links, gaps, unresolved ambiguities, and exact citations. For flag questions, hand candidates to `flag-validator` rather than constructing flags from the story.

## Safety, accuracy and scope

- **Offline analysis only**: never probe hosts, connect to PLCs, or send control commands.
- File/packet evidence may show attempted commands rather than successful changes or physical outcomes.
- A `related_to` edge is explicitly analyst asserted and is not automatically inferred by the script.
- This skill does not directly parse PCAP, Windows events, or other raw log formats; use upstream extraction first.
- Do not mistake ATT&CK for ICS tactic groupings for proof of an actual adversary objective.
- Never invent timestamps, hostnames, process effects, or CTF flags.

## Included resources

- `scripts/reconstruct_chain.py` — standard-library timeline builder, verifier, JSON and Markdown reports.
- `references/event-schema.md` — structured events and evidence rules.
- `references/investigation-workflow.md` — OT-oriented correlation checklist.
- `examples/blackout-style-events.json` — synthetic IT-to-OT example, **not evidence from a real capture**.
- `tests/test_reconstruct_chain.py` — automated regression tests.
