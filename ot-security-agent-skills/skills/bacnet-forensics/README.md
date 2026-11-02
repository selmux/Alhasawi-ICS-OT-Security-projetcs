# BACnet Forensics Agent Skill (v0.1)

An offline, Windows 11 / Linux compatible BACnet/IP forensic triage skill with zero Python package dependencies.

## Installation
Extract the `bacnet-forensics` folder alongside `pcap-forensics` and `modbus-forensics`. Python 3.9+ recommended. No TShark requirement for the included analyzer.

## Usage

```powershell
cd .\bacnet-forensics
python -m unittest discover -s tests -v
python scripts\analyze_bacnet.py "C:\path\to\BMS_ClearWater_2.pcap" --output bacnet-report.json
```

Supports multiple captures as positional arguments. Output includes endpoint conversations, service counts, the first N sampled events, and all state-change candidates. Candidate events are not proof of compromise. Full BACnet application decoding and flag recovery are not part of v0.1.
