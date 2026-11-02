# Attack Chain Reconstruction — Agent Skill #9 (v0.1)

Offline, evidence-first correlation of structured observations from PCAPs, logs, and industrial protocol decoders.

## Requirements

Python 3.9+; no third-party libraries. Windows 11 PowerShell, Linux, and macOS are supported.

## Windows quick start

```powershell
cd .\attack-chain-reconstruction
python -m unittest discover -s tests -v
python scripts\reconstruct_chain.py examples\blackout-style-events.json --output timeline.json --markdown timeline.md
```

Input files must contain events as described in `references/event-schema.md`. Multiple JSON evidence files can be listed in one command.

## Integration with other skills

1. `pcap-forensics`, `modbus-forensics`, `bacnet-forensics`, etc. extract observed events from raw captures.
2. Translate source observations to the documented event schema, preserving source packet/log references.
3. This skill sorts, groups, and records analyst-provided causal links without inventing them.
4. Use `flag-validator` to validate any recovered CTF flag against the actual source evidence.

## Limitations

Does not parse raw PCAP or arbitrary logs directly; does not independently prove a connection between events or successful industrial impact. The included example is entirely synthetic.
