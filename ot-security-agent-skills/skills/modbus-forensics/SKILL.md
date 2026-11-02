---
name: modbus-forensics
description: Investigate Modbus TCP traffic in supplied PCAP/PCAPNG files. Use for ICS/OT CTF tasks mentioning port 502, PLC coils, holding registers, Modbus function codes, unauthorized write candidates, or hidden payloads in Modbus fields.
---

# Modbus TCP Forensics

## Purpose
Analyze **offline captures only**. Recover reproducible Modbus/TCP transaction evidence, not speculative flags. Prefer the general `pcap-forensics` skill for initial triage, but this skill can run independently.

## Workflow
1. Confirm input capture, objective, and any required answer/flag format.
2. Run `python scripts/analyze_modbus.py <capture> --output report.json`.
3. Review `function_counts`, `request_routes`, `write_candidates`, and `parser_warnings`.
4. Classify writes by device, transaction ID, unit ID, register/coil address and timestamp. Compare with reads and baseline activity; do **not** equate writes with attacks.
5. Check request/response correlation and exceptions. Distinguish transmitted commands from confirmed effects.
6. If registers or coils look like encoded data, hand off evidence to `payload-decoder` (when available). Do not guess keys, text or flags.
7. When important packets are segmented, missing, or ambiguous, use Wireshark/TShark (`-d tcp.port==502,modbus` as appropriate) to reconstruct and verify.
8. Present concise findings: hosts, function codes, frames, UTC times, register addresses, values, write candidates, confidence and limitations.

## Commands (Windows PowerShell)
```powershell
python scripts\analyze_modbus.py "C:\path\capture.pcap" --output modbus-report.json
python -m unittest discover -s tests -v
```

## Safety and precision
- Use only user-supplied authorized captures and offline analysis. Never send commands to a PLC.
- Keep raw values and decimal/hex interpretations distinguishable. Modbus PDU addresses are zero-based; HMI register labels may be offset.
- A successful TCP exchange does not establish industrial process impact.
- Report uncertainties, incomplete TCP streams, and unsupported conclusions.
- Do not claim full TCP reassembly: the bundled parser decodes complete PDUs present in each TCP segment; use Wireshark for segmented data.

See `references/modbus-notes.md` for function codes and addressing details.
