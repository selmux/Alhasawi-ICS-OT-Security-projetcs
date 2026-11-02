# Siemens S7 Forensics

**AI Agent Skill for Siemens S7comm Protocol Analysis and ICS/OT Network Forensics**

A reusable, offline forensic analysis skill designed to investigate Siemens S7 communications in Industrial Control Systems (ICS), SCADA networks, and Operational Technology (OT) environments.

This skill helps cybersecurity researchers, incident responders, and OT security analysts examine PLC communications, identify potentially unauthorized control operations, and preserve packet-level forensic evidence.

## Overview

Siemens S7 Forensics analyzes PCAP and PCAPNG files containing S7comm communications.

The skill focuses on interpreting supported S7 protocol data units (PDUs), examining PLC read and write operations, identifying CPU-related commands, and highlighting potentially state-changing activities.

It follows an **evidence-first approach**: observing a command does not establish that the PLC accepted or executed it, or that the operation caused a physical process change.

## Features

- Analyze Siemens S7comm communications from PCAP and PCAPNG files.
- Identify S7comm traffic, typically associated with TCP port 102.
- Decode supported TPKT, COTP, and S7 protocol structures.
- Identify supported S7 functions and request types.
- Examine PLC read and write operations.
- Extract supported data block and memory addressing information.
- Highlight potentially state-changing operations.
- Identify supported CPU control-related commands.
- Preserve packet numbers, timestamps, and network endpoints.
- Produce structured JSON forensic reports.
- Limit displayed events while retaining overall decoded PDU counts.

## Supported Inputs

The skill accepts locally stored PCAP and PCAPNG files containing Siemens S7comm communications.

Typical investigation sources include:

- Engineering workstation-to-PLC network captures.
- SCADA and HMI communications with Siemens controllers.
- Industrial network monitoring captures.
- Evidence involving suspected unauthorized PLC programming or control requests.
- Authorized incident response investigations involving Siemens automation systems.

**Important:** The analyzer provides best-effort decoding of supported S7comm PDUs. It does not provide complete transport-session reconstruction or comprehensive interpretation of all CPU response semantics.

## Output Format

The analyzer generates a JSON report containing supported forensic observations.

| Information | Description |
|---|---|
| Capture information | Source capture and packet-processing metadata |
| Network endpoints | Source/destination addresses and ports |
| S7comm PDUs | Supported protocol messages extracted from traffic |
| S7 functions | Identified request types and operations |
| PLC addressing | Supported memory areas, data blocks, and addresses |
| State-change candidates | Potential write, control, or programming operations |
| Evidence references | Packet numbers, timestamps, and supporting protocol fields |
| Summary counts | Counts across decoded packet-local PDUs |

The `--limit` option restricts the number of events included in the report's event arrays. Summary counts continue to reflect all successfully decoded packet-local PDUs.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No third-party Python packages required.
- No TShark installation required by the bundled analyzer.
- Designed for Windows 11, Linux, and macOS.

Wireshark or TShark is recommended for independent verification of complex protocol traffic.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\siemens-s7-forensics

python --version
python -m unittest discover -s tests -v
```

Analyze a Siemens S7 capture:

```powershell
python scripts\analyze_s7.py "C:\captures\s7-traffic.pcap" --output s7-report.json
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/siemens-s7-forensics

python3 --version
python3 -m unittest discover -s tests -v
```

Analyze a Siemens S7 capture:

```bash
python3 scripts/analyze_s7.py ~/captures/s7-traffic.pcap --output s7-report.json
```

### macOS — Terminal

Use the Linux commands with Python 3.9 or later installed.

## Limiting Reported Events

For large captures, the analyzer supports a `--limit` option to reduce the size of event arrays in the JSON output.

**Windows:**

```powershell
python scripts\analyze_s7.py "C:\captures\s7-traffic.pcap" --output s7-report.json --limit 100
```

**Linux/macOS:**

```bash
python3 scripts/analyze_s7.py ~/captures/s7-traffic.pcap --output s7-report.json --limit 100
```

**Important:** Limiting the events displayed does not limit the summary counts of successfully decoded packet-local PDUs.

## Understanding the Findings

The analyzer helps identify several categories of Siemens S7 communication activity.

| Activity | Investigation relevance |
|---|---|
| PLC read operations | May reveal controller data, configuration, or process values |
| PLC write operations | May request modifications to memory or operating parameters |
| CPU control operations | May involve changes to controller operating state |
| Block-related operations | May indicate program or configuration access |
| Engineering communications | May reveal workstation interaction with PLC resources |

These categories describe possible security relevance, not confirmed malicious activity.

For example, an S7 write request does not prove that a controller accepted the data. Analysts should examine matching responses, controller diagnostics, and operational logs before drawing conclusions.

## Integration with Other Agent Skills

Siemens S7 Forensics can complement other skills in the OT Security Agent Skills collection.

| Skill | Integration purpose |
|---|---|
| PCAP Forensics | General traffic inventory, endpoint discovery, and conversation analysis |
| OT Process Analysis | Assess potential operational consequences of PLC operations |
| Attack Chain Reconstruction | Correlate S7 events with broader IT-to-OT investigation timelines |
| OT Application Forensics | Investigate relevant SCADA, HMI, and supporting application artifacts |

Additional payload interpretation tools may assist with decoding supported data values.

These skills are independently installed. Integration may require transforming output fields into another skill's expected input schema.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation covering installation, usage, testing, and limitations.
- **`SKILL.md`** — Instructions guiding compatible AI agents in selecting and executing S7comm forensic analysis.

A compatible AI agent can use `SKILL.md` to identify relevant S7comm investigations, invoke the analyzer, and interpret its findings.

Automatic discovery and execution depend on the agent platform and configuration.

## Testing

The skill includes automated unit tests using Python's built-in `unittest` framework.

**Windows:**

```powershell
python -m unittest discover -s tests -v
```

**Linux/macOS:**

```bash
python3 -m unittest discover -s tests -v
```

Run these commands from the `siemens-s7-forensics` directory.

Passing tests confirms the behavior covered by the included test cases, not complete Siemens S7 protocol coverage.

## Limitations

- Full TCP stream reassembly is not implemented.
- Segmented or fragmented transport messages may not be fully decoded.
- Not all S7comm functions and parameter structures are supported.
- Complete SZL interpretation is not provided.
- CPU response semantics may require independent verification.
- State-changing requests do not independently prove successful execution.
- The analyzer does not establish whether observed operations were authorized.
- Physical or operational impact cannot be determined solely from network traffic.
- Report event limits may omit relevant individual events from the displayed output.

For complex traffic, use Wireshark or TShark to verify packet structure, request/response relationships, and protocol interpretation.

## Security and Evidence Handling

This skill is designed for passive, offline security investigations.

- It does not transmit S7 commands or connect to live PLCs.
- Preserve original packet captures and record cryptographic hashes.
- Protect sensitive controller addresses, configurations, and process data.
- Distinguish observed requests from confirmed controller responses and operational outcomes.
- Validate significant findings using controller diagnostics, engineering records, and authorized operational evidence.
- Do not rely solely on automated analysis for safety-critical decisions.

## Project Status

**Version 0.1.0 — Experimental**

The current implementation provides foundational Siemens S7comm forensic triage, supported PDU decoding, and identification of potentially state-changing controller operations.

Future enhancements may include improved TCP stream reassembly, expanded S7 function coverage, and deeper request/response correlation.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
