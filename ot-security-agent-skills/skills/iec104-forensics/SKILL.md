---
name: iec104-forensics
description: Analyze offline IEC 60870-5-104 TCP/2404 PCAP or PCAPNG captures for ASDU types, information object addresses, command candidates, sequence numbers, and CTF evidence. Use for telecontrol, power grid SCADA and IEC-104 packet investigations.
---

# IEC-104 Forensics

## When to use
Use when a capture or question mentions IEC 60870-5-104, IEC-104, TCP port 2404, ASDUs, COT, IOA, STARTDT or SCADA telecontrol commands. Start with `pcap-forensics` for broad protocol inventory; invoke this skill to decode IEC-104 content.

## Workflow
1. Work exclusively on local, supplied evidence. Record capture name and digest where practical.
2. Run `python scripts/analyze_iec104.py PATH_TO_CAPTURE --output iec104-report.json` (multiple captures accepted).
3. Review frame types (I/S/U), ASDU Type IDs, common addresses, IOAs, causes of transmission, timestamps and sequence numbers.
4. Investigate command candidates (typically Type IDs 45–51, 58–64, 100, 101, 103 and 105). Distinguish actual process commands from interrogation and time synchronization.
5. Correlate a command with direction, select/execute, activation confirmations and any corresponding telemetry before claiming it succeeded.
6. Provide packet numbers, endpoint IPs/ports, raw value hex, clear interpretation and uncertainty.
7. For hidden encodings, pass extracted bytes to `payload-decoder`. Use `flag-validator` before stating a recovered flag is proven.

## Output contract
Report number of APDUs, suspicious IP pairs, exact packet references, ASDU Type ID + name, common address, IOA, COT, and raw data. Never fabricate PLC/RTU effects, flags, or ACKs. Mark incomplete TCP messages as requiring reassembly.

## Safe operation
Offline read-only analysis only. Do not transmit control commands to operational equipment. IEC-104's packet data is not automatically proof of maliciousness.

## References
- `references/iec104-notes.md`
- `references/limitations.md`
