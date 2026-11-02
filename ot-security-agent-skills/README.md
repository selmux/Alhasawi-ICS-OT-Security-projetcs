# OT Security Agent Skills

**Open-Source AI Agent Skills for Industrial Control Systems (ICS) and Operational Technology (OT) Cybersecurity**

A collection of reusable AI Agent Skills designed to support industrial cybersecurity investigations, network forensics, incident response, operational impact analysis, and security research.

The project combines **AI-assisted investigation, industrial protocol expertise, and practical Python forensic tools** to help researchers, OT engineers, security analysts, and incident responders analyze industrial environments more effectively.

Each skill can operate independently using its Python command-line tools or serve as a specialized capability within a compatible AI agent environment.

> **Project Status:** Experimental — Version 0.1.x. The tools are intended for authorized, passive, offline forensic investigations. Findings require independent validation.

## Objectives

- Develop reusable, modular Agent Skills for ICS/OT cybersecurity investigations.
- Automate repetitive forensic analysis and evidence extraction.
- Support industrial protocol analysis, including Modbus TCP, BACnet/IP, Siemens S7comm, and IEC 60870-5-104.
- Identify potentially suspicious commands, unauthorized control operations, and security-relevant communications.
- Interpret potential operational consequences without assuming successful command execution.
- Normalize forensic evidence into consistent formats for downstream analysis.
- Support chronological reconstruction of IT-to-OT attack sequences.
- Promote reproducible, transparent, and evidence-based cybersecurity research.

## Available Agent Skills

The current collection includes **eight specialized skills**.

| Skill | Description |
|---|---|
| **[Modbus Forensics](skills/modbus-forensics/)** | Analyzes Modbus TCP communications, register and coil operations, and potentially unauthorized PLC commands. |
| **[BACnet Forensics](skills/bacnet-forensics/)** | Investigates BACnet/IP communications, building automation controllers, and potentially state-changing operations. |
| **[Siemens S7 Forensics](skills/siemens-s7-forensics/)** | Analyzes S7comm traffic, PLC memory access, CPU-related operations, and potentially unauthorized changes. |
| **[IEC-104 Forensics](skills/iec104-forensics/)** | Investigates IEC 60870-5-104 communications, ASDUs, information object addresses, and industrial control commands. |
| **[OT Application Forensics](skills/ot-application-forensics/)** | Performs static analysis of Node-RED, Grafana, InfluxDB, and MariaDB exported artifacts. |
| **[OT Evidence Normalizer](skills/ot-evidence-normalizer/)** | Converts supported forensic JSON reports into structured evidence for process analysis and attack-chain reconstruction. |
| **[OT Process Analysis](skills/ot-process-analysis/)** | Interprets structured industrial control observations and identifies possible operational consequences. |
| **[Attack Chain Reconstruction](skills/attack-chain-reconstruction/)** | Correlates structured forensic evidence into chronological IT-to-OT investigation timelines. |

Each skill is documented independently and includes its own capabilities, usage instructions, and limitations.

## How the Skills Work Together

The collection follows an **evidence-first forensic workflow**.

```text
              Industrial Security Evidence
                           |
          +----------------+----------------+
          |                                 |
     Network Captures               Application Exports
      PCAP / PCAPNG                JSON / SQL / Text
          |                                 |
          v                                 v
   Protocol Forensic Skills        OT Application Forensics
   - Modbus Forensics                       |
   - BACnet Forensics                       |
   - Siemens S7 Forensics                   |
   - IEC-104 Forensics                      |
          |                                 |
          +----------------+----------------+
                           |
                           v
                 Structured JSON Findings
                           |
                           v
                  OT Evidence Normalizer
                           |
             +-------------+-------------+
             |                           |
             v                           v
      OT Process Analysis       Attack Chain Reconstruction
             |                           |
             +-------------+-------------+
                           |
                           v
                  Forensic Investigation
                   and Analyst Review
```

**Current integration status:** The evidence normalizer supports defined JSON input mappings. Not every analyzer's output is automatically converted in all cases, and some sources may require additional transformation or analyst preparation.

The project does not yet include a production-ready autonomous orchestration engine for the entire workflow.

## How Each Agent Skill Works

Each skill generally contains:

- **`SKILL.md`** — Instructions describing when and how a compatible AI agent should use the skill.
- **`README.md`** — Human-facing documentation for installation, usage, supported inputs, and limitations.
- **`scripts/`** — Python command-line tools for forensic analysis.
- **`references/`** — Technical references, schemas, and investigation guidance where applicable.
- **`tests/`** — Automated tests for supported functionality.
- **`examples/`** — Sample inputs where provided.

The skills support two usage approaches:

**Manual analysis:** Researchers execute the Python tools directly against authorized evidence.

**AI-assisted analysis:** Compatible AI agents use the instructions in `SKILL.md` to determine when to invoke the appropriate analysis tools.

Automatic skill discovery depends on the agent platform and its configuration.

## Project Structure

```text
ot-security-agent-skills/
├── README.md
└── skills/
    ├── attack-chain-reconstruction/
    ├── bacnet-forensics/
    ├── iec104-forensics/
    ├── modbus-forensics/
    ├── ot-application-forensics/
    ├── ot-evidence-normalizer/
    ├── ot-process-analysis/
    └── siemens-s7-forensics/
```

## Requirements

The current tools are implemented using:

- **Python 3.9 or later**
- Python standard library
- Local files containing authorized forensic evidence

No third-party Python packages are required by the current bundled analyzers.

The tools are designed for cross-platform use on Windows 11, Linux, and macOS. Compatibility should be verified in the intended environment.

Wireshark or TShark is recommended for independent packet-level validation, particularly for fragmented or unsupported protocol traffic.

## Installation

Clone the repository containing this project, or download the relevant skill folders from GitHub.

### Windows 11 — PowerShell

From the root of the cloned repository:

```powershell
cd .\ot-security-agent-skills

python --version
```

To run the Modbus Forensics tests:

```powershell
cd .\skills\modbus-forensics
python -m unittest discover -s tests -v
```

### Linux — Bash

From the root of the cloned repository:

```bash
cd ./ot-security-agent-skills

python3 --version
```

Run the Modbus Forensics tests:

```bash
cd ./skills/modbus-forensics
python3 -m unittest discover -s tests -v
```

Each skill's README provides additional examples, input requirements, and command-line instructions.

## Usage Examples

### 1. Analyze Modbus TCP Traffic

Windows:

```powershell
python scripts\analyze_modbus.py "C:\captures\modbus.pcap" --output modbus-report.json
```

Linux:

```bash
python3 scripts/analyze_modbus.py ~/captures/modbus.pcap --output modbus-report.json
```

Run these commands from the `modbus-forensics` directory.

### 2. Analyze BACnet/IP Traffic

Windows:

```powershell
python scripts\analyze_bacnet.py "C:\captures\building-network.pcap" --output bacnet-report.json
```

Linux:

```bash
python3 scripts/analyze_bacnet.py ~/captures/building-network.pcap --output bacnet-report.json
```

Run these commands from the `bacnet-forensics` directory.

### 3. Normalize Forensic Evidence

The OT Evidence Normalizer accepts supported structured JSON forensic reports.

Windows:

```powershell
python scripts\normalize_evidence.py "C:\reports\modbus.json" "C:\reports\bacnet.json" --output-dir "C:\reports\normalized"
```

Linux:

```bash
python3 scripts/normalize_evidence.py ~/reports/modbus.json ~/reports/bacnet.json --output-dir ~/reports/normalized
```

Run these commands from the `ot-evidence-normalizer` directory.

The normalizer generates:

| Output file | Purpose |
|---|---|
| `normalization-summary.json` | Processing statistics, input references, and warnings |
| `attack-chain-events.json` | Structured events for Attack Chain Reconstruction |
| `process-observations.json` | Structured observations for OT Process Analysis |

### 4. Analyze Potential Operational Consequences

From the `ot-process-analysis` directory:

```bash
python3 scripts/analyze_process.py process-observations.json --output process-report.json
```

The input must follow the schema documented in the skill's `references/input-schema.md`.

### 5. Reconstruct an Incident Timeline

From the `attack-chain-reconstruction` directory:

```bash
python3 scripts/reconstruct_chain.py attack-chain-events.json --output timeline.json --markdown timeline.md
```

The input must conform to the event schema documented in that skill.

These examples illustrate individual tool execution. Any necessary file transfers and schema transformations between skills must be handled explicitly.

## Intended Use Cases

- ICS/OT network traffic investigation
- Industrial protocol security analysis
- Unauthorized PLC command investigation
- Building automation system forensics
- SCADA communication analysis
- OT application configuration review
- Industrial process anomaly investigation
- IT-to-OT attack-chain reconstruction
- Digital forensics and incident response
- Cybersecurity research and technical training

## Current Limitations

The collection is experimental and has several known limitations:

- Some network parsers analyze complete protocol messages contained within individual packets and do not perform full TCP stream reassembly.
- Protocol decoders do not implement every function or field defined by their respective standards.
- The evidence normalizer supports selected JSON structures rather than arbitrary vendor exports.
- OT Process Analysis requires structured observations and does not independently determine plant-specific safe operating limits.
- Attack Chain Reconstruction does not establish causality without supporting evidence.
- OT Application Forensics performs static artifact triage rather than active vulnerability scanning.
- Detection of potentially state-changing commands does not prove that those commands succeeded.
- The collection has not yet undergone comprehensive validation against diverse real-world industrial incidents.

All results should be interpreted in their operational context and independently verified.

## Security and Operational Safety

These skills are designed for **passive, offline forensic analysis** of authorized evidence.

They do not intentionally issue commands to live industrial controllers, modify industrial processes, or perform active exploitation.

Users should follow good forensic and OT security practices:

- Preserve original evidence and cryptographic hashes.
- Avoid modifying source artifacts during analysis.
- Protect sensitive industrial configurations, network addresses, and credentials.
- Distinguish observed events from hypotheses and inferred consequences.
- Verify significant findings against controller, SCADA, and engineering records.
- Obtain appropriate authorization before analyzing operational data.
- Avoid relying solely on AI-generated findings for safety-critical decisions.

## Project Status and Roadmap

**Current status: Experimental — Version 0.1.x**

The first eight skills provide foundational forensic analysis, evidence normalization, and incident reconstruction capabilities.

Potential future development areas include:

- Full TCP stream reassembly for supported industrial protocols.
- Expanded protocol decoding and request/response correlation.
- Additional adapters for SIEM logs, syslog, CSV, and OT monitoring platform exports.
- Standardized evidence schemas across all skills.
- Improved asset and process context integration.
- Broader regression tests using authorized, sanitized industrial datasets.
- More comprehensive Windows and Linux integration testing.
- Optional agent orchestration for coordinated investigations.

These are planned areas of exploration rather than implemented capabilities.

## Contributing

Contributions related to industrial protocol analysis, forensic techniques, technical documentation, automated testing, and secure software development are welcome.

Please ensure that contributions follow responsible security research practices.

Do not submit confidential operational captures, proprietary configuration files, credentials, or sensitive infrastructure information.

## Maintainer

**Dr. Sulaiman Alhasawi**

ICS/OT Cybersecurity Researcher

- GitHub: https://github.com/selmux
- Website: https://zerontek.com

## Disclaimer

This project is provided for educational, research, and authorized cybersecurity investigation purposes.

The software is provided on an experimental basis without guarantees of completeness, accuracy, or suitability for operational decision-making.

Users are responsible for ensuring that their activities comply with applicable laws, organizational policies, and industrial safety requirements.

---

**Building reusable AI capabilities for safer and more resilient industrial environments.**
