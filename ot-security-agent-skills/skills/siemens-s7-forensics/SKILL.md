---
name: siemens-s7-forensics
description: Offline Siemens S7comm network forensics for PCAP and PCAPNG files. Use for ISO-on-TCP port 102, S7 PLC reads/writes, DB/merker addresses, CPU state-control requests, SZL diagnostic investigations, and Siemens PCS7/S7 forensic CTF evidence. Does not connect to devices.
---

# Siemens S7comm Forensics

## Activation
Use for offline traces involving Siemens S7 controllers, S7comm (RFC 1006 / ISO-on-TCP), PLC data blocks, OB/FC/DB references, or suspected PLC control requests. Start with the general `pcap-forensics` skill when the capture's protocols are unknown.

## Procedure
1. Identify provided PCAP/PCAPNG evidence and the question's exact requested field or flag format.
2. Run `python scripts/analyze_s7.py path/to/capture.pcap --output s7-report.json` from this skill's directory. Use a quoted path on Windows.
3. Inspect `decoded_s7_pdus`, `function_counts`, and `state_change_candidates`. Each event contains original frame, UTC time, source/destination and S7 PDU reference.
4. For `Read Var` / `Write Var` jobs, inspect `items` for DB number, area, byte offset, bit offset, and quantity. Treat values as raw bytes unless type is confirmed by context. For floats, validate endian order and IEEE-754 representation separately.
5. For CPU control, uploads/downloads, SZL/user-data, and unsuccessful responses, verify packet structure and error codes using Wireshark/TShark if available. This parser marks only selected candidates and intentionally does not claim full SZL or PLC status decoding.
6. Match request and response using endpoint, S7 PDU reference, and sequence/timestamps. Avoid treating sent requests as proof they succeeded.
7. For recovered encoded bytes, invoke `payload-decoder`. For any flag, invoke `flag-validator` and require traceable extraction evidence.
8. Report precise frame numbers, raw data, decoded values, uncertainties, and whether the answer is observed or inferred. Never fabricate flags, PLC states, or physical effects.

## Command
`python scripts/analyze_s7.py <capture> [more-captures...] [--output report.json] [--limit 100]`

## Safety and limits
Work only on offline, authorized evidence. Never connect to live PLCs. Standard-library parser supports PCAP/PCAPNG via shared `pcap_core.py` and basic TPKT/COTP/S7comm. No TCP reassembly, no S7comm Plus decoding, no complete SZL or item-data semantic decoding. See `references/protocol-notes.md` and `references/limitations.md`.
