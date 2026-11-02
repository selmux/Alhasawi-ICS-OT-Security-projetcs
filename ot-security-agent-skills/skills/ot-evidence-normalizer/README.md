# OT Evidence Normalizer

**AI Agent Skill for ICS/OT Forensic Evidence Normalization and Cross-Source Integration**

A reusable, offline evidence normalization skill designed to transform supported industrial cybersecurity forensic reports into consistent, structured JSON observations for downstream incident investigation.

The skill helps OT security analysts, incident responders, and researchers bridge the gap between industrial protocol analysis, operational impact assessment, and attack-chain reconstruction.

## Overview

Industrial cybersecurity incidents often produce evidence from multiple sources, including network captures, security monitoring tools, application logs, and controller communications.

These sources may use different formats, naming conventions, timestamp representations, and evidence structures.

**OT Evidence Normalizer** converts supported structured forensic findings into compatible formats for other analysis skills.

It follows an **evidence-first approach**: the tool preserves source references, records transformation warnings, and does not invent missing evidence or assume malicious activity.

## Features

- Normalize supported industrial protocol forensic reports.
- Process structured JSON observations from multiple sources.
- Standardize timestamps and evidence references.
- Preserve source artifact hashes and available packet references.
- Identify supported industrial operations for downstream interpretation.
- Convert observations into compatible input formats for OT Process Analysis and Attack Chain Reconstruction.
- Report unsupported records and conversion limitations.
- Process evidence offline without connecting to live industrial systems.

## Supported Inputs

Version 0.1.0 supports selected JSON structures from:

| Evidence source | Input type |
|---|---|
| Modbus Forensics | Structured Modbus TCP analysis report |
| BACnet Forensics | Structured BACnet/IP analysis report |
| Siemens S7 Forensics | Supported S7comm JSON findings |
| IEC-104 Forensics | Supported IEC-104 JSON findings |
| OT Application Forensics | Supported application artifact findings |
| Generic structured events | Supported timestamped JSON observations |

**Important:** The current version does not directly parse raw PCAP files, syslog, CSV, arbitrary log files, or vendor-specific OT monitoring platform exports.

Input compatibility depends on the implemented mapping rules.

## Output Format

The normalizer produces three JSON files.

| Output file | Description |
|---|---|
| `normalization-summary.json` | Processing summary, source information, counts, warnings, and limitations |
| `attack-chain-events.json` | Events formatted for Attack Chain Reconstruction |
| `process-observations.json` | Industrial control observations formatted for OT Process Analysis |

The results provide a standardized starting point for further investigation.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No third-party Python packages required.
- Designed for Windows 11, Linux, and macOS.
- No network connection required for analysis.

The skill operates entirely offline.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\ot-evidence-normalizer

python --version
python -m unittest discover -s tests -v
```

Normalize existing forensic reports:

```powershell
python scripts\normalize_evidence.py "C:\reports\modbus.json" "C:\reports\bacnet.json" --output-dir "C:\reports\normalized"
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/ot-evidence-normalizer

python3 --version
python3 -m unittest discover -s tests -v
```

Normalize existing forensic reports:

```bash
python3 scripts/normalize_evidence.py ~/reports/modbus.json ~/reports/bacnet.json --output-dir ~/reports/normalized
```

### macOS — Terminal

Use the Linux commands with Python 3.9 or later installed.

## How It Works

The skill acts as an integration layer between forensic data extraction and investigation analysis.

```text
       Industrial Forensic Evidence
                    |
                    v
       Protocol / Artifact Analyzers
       - Modbus Forensics
       - BACnet Forensics
       - Siemens S7 Forensics
       - IEC-104 Forensics
       - OT Application Forensics
                    |
                    v
          Structured JSON Reports
                    |
                    v
          OT Evidence Normalizer
                    |
          +---------+---------+
          |                   |
          v                   v
   Attack Chain Events   Process Observations
          |                   |
          v                   v
   Attack Chain          OT Process
   Reconstruction        Analysis
```

The normalizer is a data transformation component, not an incident detection or attribution engine.

## Integration with Other Agent Skills

| Skill | Integration purpose |
|---|---|
| Modbus Forensics | Source of supported register, coil, and control-operation findings |
| BACnet Forensics | Source of supported building automation and controller events |
| Siemens S7 Forensics | Source of supported S7comm observations |
| IEC-104 Forensics | Source of supported SCADA communications and control events |
| OT Application Forensics | Source of supported application-related findings |
| OT Process Analysis | Consumer of normalized industrial control observations |
| Attack Chain Reconstruction | Consumer of normalized chronological security events |

Not every field or event type from these tools is necessarily supported. Review conversion warnings and the source mapping documentation.

## AI Agent Integration

Each skill contains two primary documentation files:

- **`README.md`** — Human-facing installation, usage, testing, and limitation documentation.
- **`SKILL.md`** — Operational instructions guiding compatible AI agents in selecting and running the normalizer.

An AI agent can use this skill when forensic reports from different tools need to be prepared for common downstream analysis.

Automatic skill discovery and execution depend on the agent environment and configuration.

## Testing

Run the automated tests from the skill's root directory.

**Windows:**

```powershell
python -m unittest discover -s tests -v
```

**Linux/macOS:**

```bash
python3 -m unittest discover -s tests -v
```

The included tests cover supported normalization behaviors and output compatibility. Passing tests does not establish compatibility with every forensic export or real-world incident dataset.

## Limitations

- Accepts supported structured JSON inputs only.
- Does not independently decode PCAP or PCAPNG traffic.
- Does not automatically ingest arbitrary SIEM or OT monitoring platform exports.
- Not all source schemas and event types are supported.
- Records without usable timestamps may be excluded with warnings.
- Inferred operation labels require analyst verification.
- Does not independently confirm attack success, authorization status, or physical consequences.
- Does not automatically establish causal relationships between events.
- Data conversion does not prove the accuracy or completeness of the original forensic findings.

Results should be validated against the original evidence before operational or security conclusions are drawn.

## Security and Evidence Handling

This skill is designed for passive, offline forensic processing.

- It does not connect to industrial controllers or modify operational systems.
- Preserve original evidence and cryptographic hashes.
- Retain packet numbers, timestamps, and source references where available.
- Avoid inventing missing event attributes.
- Protect sensitive OT addresses, configurations, and credentials.
- Review normalized reports for confidential information before sharing.
- Distinguish observed facts from transformed or inferred classifications.

## Project Status

**Version 0.1.0 — Experimental**

The initial implementation supports selected JSON forensic report mappings and generation of compatible outputs for OT Process Analysis and Attack Chain Reconstruction.

Potential future improvements include additional schema adapters, SIEM and syslog integration, broader vendor export support, and more comprehensive cross-source validation.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
