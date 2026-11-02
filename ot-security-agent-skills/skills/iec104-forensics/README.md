# IEC-104 Forensics Agent Skill (v0.1.0)

Read-only forensic parser for standard IEC 60870-5-104 traffic in PCAP and PCAPNG files. Python 3.9+ standard library only; works on Windows 11, Linux and macOS.

## Windows / PowerShell

```powershell
cd .\iec104-forensics
python -m unittest discover -s tests -v
python scripts\analyze_iec104.py "C:\path\capture.pcap" --output iec104-report.json
```

Multiple files: `python scripts\analyze_iec104.py "C:\cap1.pcap" "C:\cap2.pcap" --output report.json`.

The script does NOT connect to any network device. It analyzes complete IEC-104 APDUs found inside individual TCP payloads; it does **not** yet implement full TCP stream reassembly. This can cause missed APDUs when the transport splits an application frame. Results are hypotheses requiring packet-level contextual verification.

Files: `SKILL.md`, `scripts/analyze_iec104.py`, `scripts/pcap_core.py`, `references/`, `tests/`.
