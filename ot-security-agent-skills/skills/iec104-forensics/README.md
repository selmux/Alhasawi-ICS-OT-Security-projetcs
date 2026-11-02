# IEC-104 Forensics

**AI Agent Skill for IEC 60870-5-104 Protocol Analysis and ICS/OT Network Forensics**

A reusable, offline forensic analysis skill designed to investigate IEC 60870-5-104 communications in Industrial Control Systems (ICS), SCADA networks, electrical utilities, and other Operational Technology (OT) environments.

This skill helps cybersecurity researchers, incident responders, and OT security analysts examine industrial communications, identify potentially unauthorized control operations, and document packet-level evidence.

## Overview

IEC-104 Forensics analyzes PCAP and PCAPNG files containing IEC 60870-5-104 network traffic.

The skill focuses on interpreting application protocol data units (APDUs), identifying control commands, examining information object addresses (IOAs), and reconstructing observable communication sequences.

It follows an **evidence-first approach**: detected control operations are investigation candidates and do not independently prove malicious activity or successful execution.

## Features

- Parse IEC 60870-5-104 traffic from PCAP and PCAPNG captures.
- Identify IEC-104 communications, typically over TCP port 2404.
- Decode supported I-format, S-format, and U-format frames.
- Identify ASDU Type IDs and Causes of Transmission (COT).
- Extract supported Information Object Addresses (IOAs).
- Identify command and setpoint operation candidates.
- Examine communication sequence numbers.
- Preserve packet numbers, timestamps, and network endpoints.
- Produce structured JSON forensic reports.
- Analyze multiple packet captures in one execution.

## Supported Inputs

The skill accepts locally stored PCAP and PCAPNG files containing IEC-104 communications.

Typical sources include:

- SCADA network packet captures.
- Control center-to-RTU communications.
- Electrical substation and utility network captures.
- Network evidence involving industrial control commands.
- Authorized OT incident response investigations.

**Important:** The current implementation analyzes complete IEC-104 APDUs contained within individual TCP payloads. It does not implement full TCP stream reassembly.

## Output Format

The analyzer generates JSON findings intended for further forensic investigation.

| Information | Description |
|---|---|
| Capture metadata | Source capture and processing information |
| Network endpoints | Source/destination IP addresses and ports |
| APCI frame information | IEC-104 frame types and supported sequence numbers |
| ASDU information | Supported Type IDs and Causes of Transmission |
| Information objects | Extracted IOAs where decoding is supported |
| Command candidates | Potential industrial control and setpoint operations |
| Packet evidence | Packet numbers and timestamps supporting observations |

Findings should be reviewed alongside the original packet capture.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No third-party Python dependencies.
- No TShark installation required by the included analyzer.
- Designed for Windows 11, Linux, and macOS.

The skill operates entirely offline and does not require access to live industrial systems.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\iec104-forensics

python --version
python -m unittest discover -s tests -v
```

Analyze an IEC-104 capture:

```powershell
python scripts\analyze_iec104.py "C:\captures\scada-traffic.pcap" --output iec104-report.json
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/iec104-forensics

python3 --version
python3 -m unittest discover -s tests -v
```

Analyze a capture:

```bash
python3 scripts/analyze_iec104.py ~/captures/scada-traffic.pcap --output iec104-report.json
```

### macOS — Terminal

Use the same commands as Linux with Python 3.9 or later installed.

## Analyzing Multiple Captures

The analyzer accepts multiple PCAP or PCAPNG files as positional arguments.

**Windows:**

```powershell
python scripts\analyze_iec104.py "C:\captures\capture1.pcap" "C:\captures\capture2.pcap" --output combined-report.json
```

**Linux/macOS:**

```bash
python3 scripts/analyze_iec104.py ~/captures/capture1.pcap ~/captures/capture2.pcap --output combined-report.json
```

The combined report can support investigation across captures, although the tool does not automatically reconstruct interrupted TCP sessions between files.

## Integration with Other Agent Skills

IEC-104 Forensics can be used with other specialized security analysis skills.

| Skill | Integration purpose |
|---|---|
| PCAP Forensics | Identify network conversations and unusual communication patterns |
| OT Process Analysis | Assess potential operational consequences of control commands |
| Attack Chain Reconstruction | Correlate IEC-104 events with broader IT/OT incident timelines |
| OT Application Forensics | Examine supporting application and configuration evidence |

Where necessary, JSON findings must be transformed into the input schemas expected by downstream tools.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation explaining installation, usage, testing, and limitations.
- **`SKILL.md`** — Operational instructions describing how a compatible AI agent should select and execute this skill.

A compatible AI agent can use the skill to inspect IEC-104 captures, analyze supported protocol fields, and prepare evidence-backed findings.

Automatic discovery and execution depend on the agent environment and its configuration.

## Testing

Automated tests use Python's built-in `unittest` framework.

**Windows:**

```powershell
python -m unittest discover -s tests -v
```

**Linux/macOS:**

```bash
python3 -m unittest discover -s tests -v
```

Run the commands from the skill's root directory.

The included tests verify supported protocol parsing behavior. Passing tests does not establish complete IEC-104 specification coverage or full compatibility with every capture.

## Limitations

- Full TCP stream reassembly is not implemented.
- IEC-104 APDUs split across TCP segments may be missed.
- The parser focuses on complete application frames found within individual TCP payloads.
- Not all ASDU types and information element structures are fully decoded.
- Unsupported or malformed frames may produce incomplete findings.
- Detected control commands do not prove successful execution or physical impact.
- The analyzer does not independently determine whether observed operations were authorized.

Results should be correlated with SCADA event logs, RTU records, operational procedures, and other authorized evidence.

## Security and Evidence Handling

This skill is designed for passive, offline cybersecurity investigations.

- It does not connect to network devices or transmit IEC-104 commands.
- Original packet captures should be preserved and hashed before analysis.
- Sensitive network topology and infrastructure information should be protected.
- Reports should distinguish observed commands from inferred intentions and outcomes.
- Safety-critical conclusions require independent operational verification.

## Project Status

**Version 0.1.0 — Experimental**

The current implementation provides foundational IEC-104 forensic triage, supported frame decoding, and identification of potentially security-relevant control operations.

Future enhancements may include full TCP reassembly, broader ASDU coverage, and improved cross-source event correlation.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
