# BACnet Forensics

**AI Agent Skill for BACnet/IP Security Analysis and Building Automation System Forensics**

A reusable, offline forensic analysis skill designed to investigate BACnet/IP communications in Building Management Systems (BMS), Building Automation Systems (BAS), and industrial operational technology (OT) environments.

This skill helps security analysts, researchers, and incident responders identify unusual BACnet communications, investigate potentially unauthorized control commands, and preserve packet-level evidence.

## Overview

BACnet Forensics analyzes packet captures containing BACnet/IP traffic and produces structured findings that support cybersecurity investigations.

The skill focuses on discovering communicating devices, identifying BACnet services, examining controller interactions, and highlighting potentially state-changing operations.

It follows an **evidence-first approach**: suspicious commands are reported as investigation candidates rather than automatically classified as malicious or successful.

## Features

- Analyze BACnet/IP traffic from PCAP and supported PCAPNG captures.
- Identify communicating IP addresses and UDP port 47808 conversations.
- Decode supported BACnet service identifiers.
- Identify potentially state-changing commands, including `writeProperty (15)` and `deviceCommunicationControl (17)`.
- Summarize BACnet service usage and endpoint communications.
- Extract supported BACnet object and property information where available.
- Preserve packet numbers, timestamps, and network endpoints.
- Generate structured JSON forensic reports.
- Analyze multiple packet captures in one execution.

## Supported Inputs

The skill accepts locally stored packet captures containing BACnet/IP traffic.

Typical investigation sources include:

- Network captures from building automation networks.
- BAS-to-controller communications.
- Building controller traffic.
- Captures containing suspected unauthorized BACnet commands.
- Network evidence collected during OT incident response.

**Note:** Protocol identification and BACnet field decoding are best-effort. Unsupported or malformed packets may not be fully decoded.

## Output Format

The analyzer generates a JSON report containing:

| Output field | Description |
|---|---|
| Capture information | Analyzed file and packet statistics |
| Endpoint conversations | BACnet/IP communication between network devices |
| Service counts | Frequency of recognized BACnet services |
| Sampled events | First N decoded events for investigation |
| State-change candidates | Potentially state-changing BACnet operations |
| Packet evidence | Packet numbers, timestamps, and source/destination information |

State-change candidates are not proof of unauthorized access or successful equipment manipulation.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No external Python dependencies.
- No TShark installation required for the included analyzer.
- Designed for Windows 11 and Linux.

The tool operates offline and does not connect to BACnet devices.

## Installation and Usage

### Windows 11 — PowerShell

From the repository root:

```powershell
cd .\ot-security-agent-skills\skills\bacnet-forensics

python --version
python -m unittest discover -s tests -v
```

Analyze a BACnet capture:

```powershell
python scripts\analyze_bacnet.py "C:\captures\building-network.pcap" --output bacnet-report.json
```

### Linux — Bash

From the repository root:

```bash
cd ./ot-security-agent-skills/skills/bacnet-forensics

python3 --version
python3 -m unittest discover -s tests -v
```

Analyze a capture:

```bash
python3 scripts/analyze_bacnet.py ~/captures/building-network.pcap --output bacnet-report.json
```

## Analyzing Multiple Captures

The analyzer accepts multiple PCAP files as positional arguments.

**Windows:**

```powershell
python scripts\analyze_bacnet.py "C:\captures\building1.pcap" "C:\captures\building2.pcap" --output combined-report.json
```

**Linux:**

```bash
python3 scripts/analyze_bacnet.py ~/captures/building1.pcap ~/captures/building2.pcap --output combined-report.json
```

The report can be used to compare communication patterns and investigate suspicious commands across captures.

## Integration with Other Agent Skills

BACnet Forensics can complement other forensic and investigation skills.

| Skill | Integration purpose |
|---|---|
| PCAP Forensics | General network traffic identification and conversation analysis |
| OT Process Analysis | Assess potential operational consequences of building automation commands |
| Attack Chain Reconstruction | Correlate BACnet observations with wider investigation timelines |
| OT Application Forensics | Examine related building automation application artifacts |

Integration between skills may require transforming JSON output into another skill's expected input schema.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation covering installation, usage, testing, and limitations.
- **`SKILL.md`** — Instructions that guide compatible AI agents in selecting and using the BACnet forensic tools.

A compatible AI coding agent can identify when BACnet analysis is appropriate, execute the Python analyzer, and interpret its findings.

Automatic skill discovery depends on the agent environment and configuration.

## Testing

The skill includes automated tests using Python's built-in `unittest` framework.

**Windows:**

```powershell
python -m unittest discover -s tests -v
```

**Linux:**

```bash
python3 -m unittest discover -s tests -v
```

Run tests from the `bacnet-forensics` directory.

## Limitations

- BACnet decoding is best-effort and does not implement the complete BACnet specification.
- Full segmented-message reassembly is not supported in version 0.1.
- Not all BACnet object properties and application parameters are decoded.
- Some protocol identification depends on UDP port conventions and recognizable packet structures.
- State-changing operations are identified as candidates rather than confirmed malicious activity.
- A command observed in a packet capture does not independently establish that the receiving controller executed it.
- Analysis does not prove operational or physical impact.

The results should be correlated with controller logs, BAS configurations, maintenance records, and other authorized evidence.

## Security and Evidence Handling

This skill is designed for passive, offline analysis.

- It does not send commands to live BACnet controllers.
- Original captures should be preserved and hashed before analysis.
- Reports should avoid disclosing sensitive building automation configurations unnecessarily.
- Findings should distinguish observed network activity from inferred intent or operational effects.
- Industrial safety and physical security decisions require independent verification.

## Project Status

**Version 0.1 — Experimental**

The current implementation provides BACnet/IP forensic triage and supported service decoding. Additional BACnet protocol coverage, deeper object interpretation, and improved forensic correlation may be introduced in future versions.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
