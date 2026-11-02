# OT Process Analysis

**AI Agent Skill for Industrial Process Security Analysis and Operational Impact Assessment**

A reusable, offline analysis skill designed to interpret security-relevant industrial control observations in Industrial Control Systems (ICS) and Operational Technology (OT) environments.

This skill helps cybersecurity researchers, OT engineers, incident responders, and security analysts understand the potential operational consequences of observed control commands, equipment state changes, and process-related events.

## Overview

OT Process Analysis evaluates structured forensic observations extracted from industrial network communications and other authorized evidence sources.

The skill focuses on interpreting potentially significant industrial control activities, including setpoint changes, equipment start/stop requests, alarm-related operations, and interlock modifications.

It follows an **evidence-first approach**: identifying a control command does not establish that the command was accepted, executed, or caused a physical process change.

The skill complements protocol-specific forensic tools rather than replacing them.

## Features

- Analyze structured JSON observations of industrial control activity.
- Identify potentially significant setpoint and control operations.
- Interpret supported PLC register and coil changes.
- Evaluate possible consequences of equipment start/stop commands.
- Highlight observations involving alarms and interlocks.
- Associate observations with potential operational consequences.
- Preserve source evidence references provided in the input.
- Generate structured JSON reports for further investigation.
- Operate offline without connecting to industrial controllers.

## Supported Inputs

The skill accepts structured JSON files containing verified industrial control observations.

Typical sources include:

- Modbus TCP register and coil operations.
- BACnet/IP building automation commands.
- Siemens S7comm PLC data operations.
- IEC 60870-5-104 control commands and setpoint requests.
- Analyst-verified equipment state observations.
- Structured forensic findings from related OT investigations.

All input files must follow the schema documented in [`references/input-schema.md`](references/input-schema.md).

**Important:** This skill does not directly analyze PCAP files. Protocol observations must first be extracted and converted into the supported JSON schema.

## Output Format

The analyzer produces a structured JSON report containing interpretations of the supplied observations.

| Information | Description |
|---|---|
| Input observations | Industrial control events supplied for analysis |
| Operation classification | Categorization of supported industrial activities |
| Potential consequences | Possible operational implications of observed commands |
| Evidence references | Source packet or artifact references supplied in the input |
| Evidence limitations | Uncertainty and restrictions on interpreting observations |

Results are intended to support investigation, not replace engineering verification or safety assessments.

## Requirements

- Python 3.9 or later.
- Python standard library only.
- No third-party Python packages required.
- Designed for Windows 11, Linux, and macOS.

The skill operates offline and does not require access to live PLCs, SCADA systems, or industrial controllers.

## Installation and Usage

### Windows 11 — PowerShell

Open PowerShell from the repository root:

```powershell
cd .\ot-security-agent-skills\skills\ot-process-analysis

python --version
python -m unittest discover -s tests -v
```

Run the included synthetic example:

```powershell
python scripts\analyze_process.py examples\sample-observations.json --output process-report.json
```

### Linux — Bash

Open a terminal from the repository root:

```bash
cd ./ot-security-agent-skills/skills/ot-process-analysis

python3 --version
python3 -m unittest discover -s tests -v
```

Run the included synthetic example:

```bash
python3 scripts/analyze_process.py examples/sample-observations.json --output process-report.json
```

### macOS — Terminal

Use the same commands as Linux with Python 3.9 or later installed.

## Analyzing Your Own Evidence

Prepare a JSON file containing verified industrial control observations that conform to the documented input schema.

**Windows:**

```powershell
python scripts\analyze_process.py "C:\evidence\observations.json" --output process-report.json
```

**Linux/macOS:**

```bash
python3 scripts/analyze_process.py ~/evidence/observations.json --output process-report.json
```

The resulting JSON report contains supported classifications and potential operational consequences.

For the exact input structure and required fields, consult [`references/input-schema.md`](references/input-schema.md).

## Understanding the Findings

OT Process Analysis focuses on the potential significance of industrial control operations.

| Observation type | Potential security or operational significance |
|---|---|
| Setpoint modification | May alter a controlled process variable or operating target |
| Coil or discrete output write | May request changes to equipment or actuator states |
| Start/stop command | May affect equipment availability or operating sequences |
| Alarm-related operation | May affect monitoring, notification, or operator awareness |
| Interlock-related operation | May affect protective or process-control logic |

These are general interpretive categories, not confirmations of actual equipment behavior.

The significance of an operation depends on the specific industrial process, controller configuration, operating state, and supporting evidence.

For example, observing a command that requests a pump stop does not establish that the pump stopped. Independent telemetry or equipment records are required to confirm the outcome.

## Integration with Other Agent Skills

OT Process Analysis is designed to complement other skills in the OT Security Agent Skills collection.

| Skill | Contribution |
|---|---|
| PCAP Forensics | Network communication evidence and endpoint information |
| Modbus Forensics | Register reads/writes and coil operations |
| BACnet Forensics | Building automation commands and controller interactions |
| Siemens S7 Forensics | PLC data operations and CPU-related activity |
| IEC-104 Forensics | SCADA control operations and telemetry observations |
| Attack Chain Reconstruction | Correlation of process-related observations with broader incident timelines |

Integration currently requires converting source findings into the input schema. Automatic integration between all skills is not implemented in version 0.1.

## AI Agent Integration

The skill contains two primary documentation files:

- **`README.md`** — Human-facing documentation covering installation, usage, testing, and limitations.
- **`SKILL.md`** — Operational instructions describing when and how a compatible AI agent should apply the skill.

An AI agent can use `SKILL.md` to determine when industrial process interpretation is appropriate, prepare compatible input observations, and execute the analysis script.

Automatic skill discovery and execution depend on the agent platform and its configuration.

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

Run these commands from the `ot-process-analysis` directory.

The included tests evaluate supported classifications and report generation. Passing tests does not establish that interpretations are valid for every industrial environment or operating condition.

## Limitations

- Does not directly parse PCAP or PCAPNG files.
- Requires structured JSON observations conforming to the documented schema.
- Does not automatically integrate with protocol-specific analysis skills.
- Does not infer plant-specific operating thresholds or safe process limits.
- Does not interpret PLC ladder logic or validate controller programs.
- Does not independently confirm command execution.
- Does not verify actual equipment states or physical consequences.
- Does not replace process engineering expertise, hazard analysis, or operational safety assessments.

The analyzer should not be used as the sole basis for safety-critical or operational decisions.

## Security and Evidence Handling

This skill is designed for passive, offline analysis.

- It does not communicate with or modify live industrial systems.
- Preserve original evidence and maintain appropriate chain-of-custody procedures.
- Ensure that supplied observations accurately represent the original forensic sources.
- Distinguish observed commands from confirmed process changes.
- Avoid exposing sensitive operating parameters, plant configurations, or infrastructure details in public reports.
- Validate operational consequences using independent telemetry, controller records, and process engineering expertise.

## Project Status

**Version 0.1 — Experimental**

The current implementation provides foundational interpretation of structured industrial control observations and identifies potential operational consequences.

Future enhancements may include additional industrial-process categories, broader input normalization, and improved correlation with protocol-specific forensic findings.

---

Part of the **OT Security Agent Skills** open-source initiative.

Maintained by **Dr. Sulaiman Alhasawi**.

GitHub: https://github.com/selmux
