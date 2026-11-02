# OT Security Agent Skills

**Open-Source AI Agent Skills for Industrial Control Systems (ICS) and Operational Technology (OT) Cybersecurity**

A collection of reusable AI Agent Skills designed to support industrial cybersecurity investigations, network forensics, incident response, and security research.

The project brings together **AI-assisted analysis, industrial protocol expertise, and practical forensic tools** to help security researchers, OT engineers, and incident responders investigate industrial environments more efficiently.

## Objectives

- Develop reusable Agent Skills for ICS/OT cybersecurity investigations.
- Automate repetitive forensic analysis and evidence extraction.
- Support industrial protocol analysis, including Modbus TCP, BACnet/IP, Siemens S7comm, and IEC 60870-5-104.
- Assist with identifying suspicious activities, unauthorized control commands, and potential operational impacts.
- Support investigation of IT-to-OT attack chains.
- Promote transparent, reproducible, and evidence-based security research.

## Agent Skills

The project is organized into specialized skills, each addressing a specific area of OT cybersecurity.

| Skill | Description |
|---|---|
| **Modbus Forensics** | Analyze Modbus TCP communications, register operations, coil manipulation, and suspicious PLC commands. |
| **BACnet Forensics** | Investigate BACnet/IP communications, building automation controllers, and unauthorized control operations. |
| **Siemens S7 Forensics** | Analyze S7comm traffic, PLC data access, CPU operations, and potential unauthorized modifications. |
| **IEC-104 Forensics** | Investigate IEC 60870-5-104 communications, telemetry, control commands, and information object addresses. |
| **OT Process Analysis** | Interpret industrial control activity and assess potential effects on operational processes. |
| **OT Application Forensics** | Analyze artifacts from applications such as Node-RED, Grafana, InfluxDB, and MariaDB. |
| **Attack Chain Reconstruction** | Correlate forensic evidence and reconstruct chronological IT-to-OT attack sequences. |

Additional skills may be introduced as the project evolves.

## How It Works

Each Agent Skill combines:

- **SKILL.md:** Instructions describing when and how an AI agent should use the skill.
- **Python tools:** Reusable scripts for forensic analysis and evidence extraction.
- **Reference materials:** Technical documentation and investigation procedures.
- **Tests:** Automated checks to help maintain reliable and reproducible results.

The skills are intended for use with compatible AI coding agents and can also be operated through standalone Python command-line tools.

## Project Structure

```text
ot-security-agent-skills/
├── README.md
└── skills/
    ├── modbus-forensics/
    ├── bacnet-forensics/
    ├── siemens-s7-forensics/
    ├── iec104-forensics/
    ├── ot-process-analysis/
    ├── ot-application-forensics/
    └── attack-chain-reconstruction/
```

## Intended Use Cases

- ICS/OT network traffic investigation
- Industrial protocol security analysis
- Unauthorized PLC command detection
- OT incident response and digital forensics
- Industrial process anomaly investigation
- IT/OT attack-chain reconstruction
- Cybersecurity research and technical training

## Security and Operational Safety

These tools are intended primarily for **passive, offline forensic analysis** of authorized evidence.

They are not designed to issue commands to live industrial controllers or modify operational processes.

AI-generated findings should be independently validated before being used in operational, safety-critical, or incident-response decisions.

## Project Status

**Experimental — Initial Development**

The initial skills are being developed and evaluated. Features, interfaces, and analysis capabilities may change as the project matures.

Community feedback, testing, and technical contributions are welcome.

## Contributing

Contributions related to industrial protocol analysis, forensic techniques, documentation, testing, and research are welcome.

Please ensure that contributions follow responsible security research practices and do not include confidential operational data or unauthorized access techniques.

## Maintainer

**Dr. Sulaiman Alhasawi**

ICS/OT Cybersecurity Researcher

- GitHub: https://github.com/selmux
- Website: https://zerontek.com

## Disclaimer

This project is provided for educational, research, and authorized cybersecurity investigation purposes.

Users are responsible for ensuring that their activities comply with applicable laws, organizational policies, and operational safety requirements.

---

**Building reusable AI capabilities for safer and more resilient industrial environments.**
