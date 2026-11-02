# Siemens S7 Forensics — Agent Skill #6 (v0.1.0)

Portable offline PCAP/PCAPNG S7comm triage using Python standard library only. No traffic is transmitted.

## Windows 11

```powershell
cd .\siemens-s7-forensics
python -m unittest discover -s tests -v
python scripts\analyze_s7.py "C:\path\to\northgate_wtp_attack.pcap" --output s7-report.json
```

The report includes S7comm PDUs, functions, state-change candidates and evidence references. With `--limit`, event arrays are truncated while summary counts cover all decoded packet-local PDUs.

## Linux / macOS

```sh
python3 -m unittest discover -s tests -v
python3 scripts/analyze_s7.py /path/to/capture.pcap --output s7-report.json
```

Use alongside `pcap-forensics` (inventory), `payload-decoder` (encoded payloads), and `flag-validator` (evidence checking). These tools are independently installed; no hard dependencies between skills.

This is **best-effort forensic triage**, not a substitute for Wireshark/TShark and manual validation of segmented packets or CPU response semantics.
