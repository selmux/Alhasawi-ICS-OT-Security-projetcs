# Attack Chain Reconstruction

**AI Agent Skill for ICS/OT Cybersecurity Incident Reconstruction and Evidence Correlation**

A reusable, offline forensic analysis skill designed to reconstruct chronological attack sequences from structured cybersecurity evidence.

This skill supports ICS/OT security researchers, incident responders, and forensic analysts investigating suspicious network activities, lateral movement, unauthorized industrial control operations, and potential IT-to-OT compromises.

## Overview

Attack Chain Reconstruction correlates structured observations collected from network captures, system logs, industrial protocol analyzers, and other forensic sources.

It helps analysts organize events into chronological timelines, preserve evidence references, and document relationships between observed activities.

The skill follows an **evidence-first approach**: it does not invent missing events, assume causality, or claim successful attacks without supporting evidence.

## Features

- Correlate events from multiple structured JSON evidence files.
- Normalize event timestamps and organize chronological timelines.
- Combine observations from IT and OT security investigations.
- Preserve original evidence references, including packet numbers and log entries.
- Document analyst-provided relationships between events.
- Generate machine-readable JSON and human-readable Markdown reports.
- Support downstream AI-assisted incident investigation.

## Supported Inputs

The skill accepts structured JSON evidence files containing forensic events.

Typical evidence sources include:

- Network traffic observations extracted from PCAP/PCAPNG files.
- Firewall, authentication, and operating system logs.
- Modbus TCP, BACnet/IP, Siemens S7comm, and IEC-104 forensic findings.
- Application and database security events.
- Analyst-generated investigation records.

Input files must follow the event structure described in [`references/event-schema.md`](references/event-schema.md).

**Note:** Raw PCAP files and arbitrary unstructured logs must be processed by appropriate forensic tools before being supplied to this skill.

## Output Format

The analyzer can generate:

| Output | Description |
|---|---|
| JSON report | Structured events, chronological ordering, and documented relationships |
| Markdown report | Human-readable investigation timeline |
| Evidence references | References to original packet captures, logs, and supporting artifacts |

The reports are intended to support analyst review, incident documentation, and subsequent forensic analysis.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No external Python packages required.
- Designed for Windows 11, Linux, and macOS.

The skill performs offline analysis and does not require network connectivity.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\attack-chain-reconstruction

python --version
python -m unittest discover -s tests -v
```

Run the included synthetic example:

```powershell
python scripts\reconstruct_chain.py examples\blackout-style-events.json --output timeline.json --markdown timeline.md
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/attack-chain-reconstruction

python3 --version
python3 -m unittest discover -s tests -v
```

Run the included synthetic example:

```bash
python3 scripts/reconstruct_chain.py examples/blackout-style-events.json --output timeline.json --markdown timeline.md
```

### macOS — Terminal

Use the same commands as Linux, provided Python 3.9+ is available.

## Analyzing Multiple Evidence Files

Multiple JSON evidence files can be supplied to reconstruct a combined timeline.

**Windows:**

```powershell
python scripts\reconstruct_chain.py evidence1.json evidence2.json --output combined-timeline.json --markdown combined-timeline.md
```

**Linux/macOS:**

```bash
python3 scripts/reconstruct_chain.py evidence1.json evidence2.json --output combined-timeline.json --markdown combined-timeline.md
```

All input files must conform to the documented event schema.

## Integration with Other Agent Skills

Attack Chain Reconstruction can consume structured findings produced or adapted from other forensic skills.

| Skill | Contribution |
|---|---|
| PCAP Forensics | Network conversations, endpoints, timestamps, and packet references |
| Modbus Forensics | PLC register operations, coil writes, and Modbus activity |
| BACnet Forensics | Building automation events and controller commands |
| Siemens S7 Forensics | PLC data access, CPU operations, and S7 communications |
| IEC-104 Forensics | SCADA telemetry, control commands, and information object addresses |
| OT Application Forensics | Application configurations and security-relevant observations |
| OT Process Analysis | Interpretations of potential operational consequences |

**Integration requires converting source findings into the event schema.** Automatic conversion from every analyzer's native output is not currently implemented.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation covering installation, command-line usage, testing, and limitations.
- **`SKILL.md`** — Operational instructions describing when and how a compatible AI agent should invoke the skill.

An AI agent can use `SKILL.md` to guide evidence correlation and choose appropriate command-line analysis steps.

Automatic skill discovery and execution depend on the agent platform and its configuration.

## Testing

The skill includes automated unit tests implemented using Python's built-in `unittest` framework.

**Windows:**

```powershell
python -m unittest discover -s tests -v
```

**Linux/macOS:**

```bash
python3 -m unittest discover -s tests -v
```

Run these commands from the skill's root directory.

The included example evidence is synthetic and is intended for functional testing and demonstration.

## Limitations

- Does not directly parse raw PCAP files or arbitrary unstructured logs.
- Requires structured JSON inputs conforming to the documented schema.
- Does not independently establish causal relationships between events.
- Does not prove successful unauthorized access or industrial process impact.
- Does not automatically resolve conflicting or incomplete evidence.
- Does not guarantee that findings from other skills share a compatible schema without transformation.

Results should be reviewed by a qualified analyst and correlated with additional evidence when necessary.

## Security and Evidence Handling

This skill is designed for passive, offline investigations.

- No commands are transmitted to industrial controllers or operational systems.
- Original forensic evidence should be preserved and independently hashed.
- Sensitive information and credentials should not be included in publicly shared investigation reports.
- Findings should distinguish observed activity from interpretation or hypothesis.
- Operational and safety-related conclusions require independent verification.

## Project Status

**Version 0.1 — Experimental**

This skill is under active development. Its parsing, reporting, and correlation capabilities may be expanded as the wider OT Security Agent Skills project evolves.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
