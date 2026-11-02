# OT Application Forensics

**AI Agent Skill for ICS/OT Application Security Analysis and Digital Forensics**

A reusable, offline forensic analysis skill designed to investigate application artifacts from Node-RED, Grafana, InfluxDB, and MariaDB in Industrial Control Systems (ICS) and Operational Technology (OT) environments.

This skill supports cybersecurity researchers, incident responders, and OT security analysts investigating automation configurations, data historian artifacts, application security events, and potential credential exposure.

## Overview

OT Application Forensics performs static analysis of locally stored application exports and textual evidence.

The skill focuses on identifying security-relevant configurations, application references, potentially sensitive fields, and forensic indicators that may contribute to a broader industrial cybersecurity investigation.

It follows an **evidence-first approach**: reported findings are investigation candidates and do not independently prove unauthorized access, exploitation, or operational impact.

## Features

- Analyze Node-RED flow configuration exports.
- Inspect Grafana dashboard and datasource-related JSON artifacts.
- Examine InfluxDB line-protocol text exports.
- Review MariaDB SQL dumps and statements for security-relevant information.
- Identify potentially exposed credentials and sensitive configuration fields.
- Redact supported sensitive fields in generated reports.
- Analyze multiple files in a single execution.
- Produce structured JSON findings for forensic review.
- Operate offline without connecting to production applications or databases.

## Supported Inputs

The skill accepts locally stored text-based application artifacts.

| Application | Typical input |
|---|---|
| Node-RED | Flow configuration JSON |
| Grafana | Dashboard and configuration JSON |
| InfluxDB | Line-protocol text exports |
| MariaDB | SQL dumps and SQL statements |

Other text-based artifacts may be inspected where supported by the analyzer, but full parsing of arbitrary file formats is not guaranteed.

**Important:** This is static artifact triage, not an active vulnerability scanner, database client, or network protocol decoder.

## Output Format

The analyzer produces structured JSON reports containing security-relevant observations.

| Information | Description |
|---|---|
| Input artifact | Source filename and artifact information |
| Application indicators | Recognized application-related references |
| Configuration findings | Relevant configuration entries and service references |
| Sensitive fields | Potential credential or secret exposure, with supported redaction |
| Evidence locations | Source-file locations where available |
| Forensic findings | Structured observations for analyst review |

Sensitive fields are redacted where the current implementation recognizes them. Redaction is best-effort and should not be treated as a guarantee that every secret has been removed.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No third-party Python packages required.
- Designed for Windows 11, Linux, and macOS.

The skill operates offline and does not require access to live OT applications or databases.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\ot-application-forensics

python --version
python -m unittest discover -s tests -v
```

Run the included example:

```powershell
python scripts\analyze_apps.py examples\sample-flow.json --output report.json
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/ot-application-forensics

python3 --version
python3 -m unittest discover -s tests -v
```

Run the included example:

```bash
python3 scripts/analyze_apps.py examples/sample-flow.json --output report.json
```

### macOS — Terminal

Use the Linux commands with Python 3.9 or later installed.

## Analyzing Multiple Artifacts

The analyzer accepts multiple input files as positional arguments.

**Windows:**

```powershell
python scripts\analyze_apps.py flow.json dashboard.json dump.sql --output findings.json
```

**Linux/macOS:**

```bash
python3 scripts/analyze_apps.py flow.json dashboard.json dump.sql --output findings.json
```

This allows analysts to investigate application artifacts from multiple sources in one execution.

## Understanding the Findings

The analyzer focuses on several categories of application evidence.

| Application | Investigation focus |
|---|---|
| **Node-RED** | Automation flows, function nodes, configuration references, and connected services |
| **Grafana** | Dashboard structures, datasource references, and configuration details |
| **InfluxDB** | Measurements, timestamps, and line-protocol data |
| **MariaDB** | SQL statements, database structures, and potentially sensitive information |

Findings should be reviewed in the context of the organization's authorized configurations and operational procedures.

For example, a database connection or configured service endpoint is not inherently suspicious. Its security significance depends on authorization, intended use, and supporting evidence.

## Integration with Other Agent Skills

OT Application Forensics can complement other skills in the OT Security Agent Skills collection.

| Skill | Integration purpose |
|---|---|
| PCAP Forensics | Correlate application artifacts with observed network communications |
| Modbus Forensics | Investigate relationships between applications and PLC communications |
| BACnet Forensics | Correlate automation configurations with building controller activity |
| OT Process Analysis | Assess potential operational consequences of application-related observations |
| Attack Chain Reconstruction | Combine application findings with wider IT-to-OT investigation timelines |

Integration may require converting the generated findings into another skill's expected input schema.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation covering installation, command-line usage, testing, and limitations.
- **`SKILL.md`** — Operational instructions guiding compatible AI agents in selecting and executing application forensic analysis.

An AI agent can use the skill to inspect supported artifacts, execute the analyzer, and interpret its structured findings.

Automatic skill discovery and execution depend on the agent environment and configuration.

For artifact-specific forensic guidance, consult [`references/artifacts.md`](references/artifacts.md).

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

Run tests from the `ot-application-forensics` directory.

Passing tests confirms the functionality covered by the test cases; it does not establish exhaustive support for every application export format or configuration variant.

## Limitations

- Performs static analysis of exported files only.
- Does not connect to live Node-RED, Grafana, InfluxDB, or MariaDB instances.
- Does not perform vulnerability scanning or exploitation.
- Does not decode raw application network traffic from PCAP files.
- Does not implement a complete SQL parser.
- Application-specific detection is best-effort.
- Sensitive-field redaction may not identify every secret or credential.
- Findings do not independently prove that a configured action executed.
- Application configurations alone do not establish unauthorized activity or industrial process impact.

The results should be correlated with application logs, network evidence, authentication records, and operational documentation where available.

## Security and Evidence Handling

This skill is designed for passive, offline cybersecurity investigations.

- It does not alter application configurations or database contents.
- Preserve original forensic artifacts and record their cryptographic hashes.
- Treat configuration exports and database dumps as potentially sensitive.
- Review reports for residual credentials, tokens, internal addresses, and proprietary information before sharing them.
- Do not upload confidential OT artifacts to public repositories.
- Distinguish observed configuration values from inferred security implications.
- Validate safety-related conclusions against independent operational evidence.

## Project Status

**Version 0.1.0 — Experimental**

The current implementation provides foundational static artifact triage for Node-RED, Grafana, InfluxDB, and MariaDB.

Future enhancements may include expanded application coverage, more comprehensive artifact parsing, and improved correlation with OT network forensic findings.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
