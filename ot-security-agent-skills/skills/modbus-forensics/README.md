# Modbus Forensics

**AI Agent Skill for Modbus TCP Security Analysis and ICS/OT Network Forensics**

A reusable, offline forensic analysis skill designed to investigate Modbus TCP communications in Industrial Control Systems (ICS), SCADA networks, and Operational Technology (OT) environments.

This skill helps cybersecurity researchers, incident responders, and OT security analysts examine industrial network traffic, identify potentially unauthorized PLC operations, and preserve packet-level forensic evidence.

## Overview

Modbus Forensics analyzes PCAP and PCAPNG files containing Modbus TCP communications.

The skill focuses on identifying communicating devices, interpreting Modbus function codes, examining register and coil operations, and highlighting potentially state-changing commands.

It follows an **evidence-first approach**: detected writes and control operations are investigation candidates, not automatic proof of malicious activity or successful process manipulation.

## Features

- Analyze Modbus TCP traffic from PCAP and PCAPNG captures.
- Identify Modbus communications, typically over TCP port 502.
- Decode supported Modbus Application Data Units (ADUs).
- Extract Modbus transaction IDs, unit IDs, and function codes.
- Identify supported holding-register and coil operations.
- Extract register addresses, quantities, and values where supported.
- Identify potentially state-changing write operations.
- Preserve packet numbers, timestamps, and network endpoints.
- Generate structured JSON forensic reports.
- Support analysis of industrial network traffic without connecting to live devices.

## Supported Inputs

The skill accepts locally stored PCAP and PCAPNG files containing Modbus TCP communications.

Typical investigation sources include:

- SCADA-to-PLC network captures.
- PLC and HMI communications.
- Industrial network monitoring captures.
- Evidence of suspected unauthorized register or coil modifications.
- Authorized OT incident response investigations.

**Important:** The current parser analyzes complete Modbus ADUs contained within individual TCP segments. It does not implement full TCP stream reassembly.

## Output Format

The analyzer generates structured JSON findings for further investigation.

| Information | Description |
|---|---|
| Capture metadata | Input capture and packet-processing information |
| Network endpoints | Source and destination IP addresses and ports |
| Modbus operations | Recognized function codes and request details |
| Register operations | Supported register addresses, quantities, and values |
| Coil operations | Supported coil addresses and requested states |
| Write candidates | Potentially state-changing operations requiring review |
| Packet evidence | Packet numbers, timestamps, and supporting protocol fields |

The output is intended for analyst review and correlation with additional forensic evidence.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No third-party Python packages required.
- No TShark installation required by the bundled parser.
- Designed for Windows 11 and Linux.

Wireshark or TShark is recommended for independently verifying complex or fragmented communications.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\modbus-forensics

python --version
python -m unittest discover -s tests -v
```

Analyze a Modbus TCP capture:

```powershell
python scripts\analyze_modbus.py "C:\captures\modbus-traffic.pcap" --output modbus-report.json
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/modbus-forensics

python3 --version
python3 -m unittest discover -s tests -v
```

Analyze a Modbus TCP capture:

```bash
python3 scripts/analyze_modbus.py ~/captures/modbus-traffic.pcap --output modbus-report.json
```

## Understanding the Results

The JSON report contains observations derived from the captured Modbus traffic.

Common operations of interest include:

| Function code | Operation | Security relevance |
|---|---|---|
| 01 | Read Coils | Reveals discrete output states |
| 02 | Read Discrete Inputs | Reveals discrete input states |
| 03 | Read Holding Registers | Reads process or configuration values |
| 04 | Read Input Registers | Reads input measurements |
| 05 | Write Single Coil | May change a discrete output |
| 06 | Write Single Register | May modify a setpoint or configuration value |
| 15 | Write Multiple Coils | May change multiple discrete outputs |
| 16 | Write Multiple Registers | May modify multiple process values |

These are standard Modbus function codes. Actual decoding coverage depends on the implemented parser.

**A Modbus write is not inherently malicious.** Authorization, process context, response status, and supporting operational evidence must be considered.

## Integration with Other Agent Skills

Modbus Forensics can complement other forensic investigation skills.

| Skill | Integration purpose |
|---|---|
| PCAP Forensics | General traffic inspection, endpoints, and network conversations |
| OT Process Analysis | Assess potential operational consequences of register and coil changes |
| Attack Chain Reconstruction | Correlate Modbus activity with broader IT/OT incident timelines |
| OT Application Forensics | Investigate supporting HMI, historian, and automation application artifacts |

Integration may require converting the Modbus JSON findings into another skill's expected input schema.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation describing installation, usage, testing, and limitations.
- **`SKILL.md`** — Operational instructions guiding compatible AI agents in selecting and executing Modbus forensic analysis.

A compatible AI coding agent can use `SKILL.md` to determine when Modbus traffic analysis is appropriate and invoke the bundled Python tools.

Automatic skill discovery and execution depend on the agent platform and its configuration.

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

Run these commands from the skill's root directory.

Passing the included tests confirms the tested functionality, but does not establish complete Modbus protocol coverage.

## Limitations

- Full TCP stream reassembly is not implemented.
- Modbus ADUs split across TCP segments may not be decoded.
- The parser focuses on complete application messages contained within individual TCP payloads.
- Unsupported or malformed protocol messages may produce incomplete findings.
- Detected write operations do not independently prove unauthorized access.
- A write request does not establish that the receiving PLC successfully applied the requested change.
- Physical or operational impact cannot be confirmed from network traffic alone.
- The tool does not automatically determine whether observed activity violates site-specific security policies.

For fragmented or complex traffic, inspect the original capture using Wireshark or TShark.

## Security and Evidence Handling

This skill is intended for passive, offline cybersecurity investigations.

- It does not transmit Modbus commands or connect to live industrial devices.
- Preserve original packet captures before performing analysis.
- Record evidence hashes and maintain appropriate chain-of-custody procedures.
- Protect sensitive infrastructure addresses, operational configurations, and process information.
- Clearly distinguish observed network activity from inferred intent or consequences.
- Validate safety-critical findings against operational records and controller evidence.

## Project Status

**Version 0.1 — Experimental**

The current implementation provides foundational Modbus TCP forensic triage, supported register and coil decoding, and identification of potentially state-changing operations.

Future improvements may include TCP stream reassembly, broader protocol support, and deeper cross-source investigation capabilities.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
