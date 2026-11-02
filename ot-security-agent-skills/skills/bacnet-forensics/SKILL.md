---
name: bacnet-forensics
description: Forensic analysis of offline BACnet/IP PCAP or PCAPNG captures. Use when traffic contains BACnet UDP/47808, building automation, BMS/BAS devices, Who-Is/I-Am, ReadProperty, WriteProperty, or DeviceCommunicationControl. Extract packet-level evidence and identify potential state-changing commands without making unsupported compromise claims.
---

# BACnet/IP Forensics

## Scope
Use on supplied capture files in authorized CTF/lab/defensive investigations. Work offline. Never interact with live BACnet controllers. Pair with `pcap-forensics` for broad traffic triage and with `payload-decoder` (when available) for embedded encoded fragments.

## Workflow
1. Inventory available PCAP/PCAPNG files and validate they are readable.
2. Run `python scripts/analyze_bacnet.py capture.pcap --output bacnet-report.json` (on Windows: `python scripts\analyze_bacnet.py capture.pcap --output bacnet-report.json`).
3. Separate regular BAS polling from late-appearing or unusual controllers and clients using timeline and endpoint evidence.
4. Review `state_change_candidates`: WriteProperty (15), WritePropertyMultiple (16), DeviceCommunicationControl (17), ReinitializeDevice (20), and object create/delete. These **may** be legitimate; don't label them malicious based solely on service choice.
5. Correlate client requests with replies by IP endpoints, invoke ID, timestamps and service. Consider broadcast discovery and segmented PDUs.
6. For each finding, cite actual capture filename and frame number. Report UTC timestamps and raw context when available. If object/property fields are absent or ambiguous, say so.
7. Answer the precise question, and verify any flag against evidence. Do not invent flags or accept speculative decoding.

## CLI
`python scripts/analyze_bacnet.py <capture> [additional-captures...] [--output report.json] [--max-events 30]`

## Evidence standard
Include source/destination IP, BACnet service name and numeric service choice (Wireshark notation), frame ID, UTC time, object identifier/property when confirmed, and the reason for suspicion. Distinguish observations from conclusions. Escalate undecoded or fragmented data to Wireshark/TShark for manual review.

## Limits
Python stdlib implementation currently handles Ethernet, IPv4, UDP BACnet/IP and best-effort unsegmented APDUs. No full IP or BACnet segmentation reassembly, no IPv6, no BACnet/SC, and no conclusive access-control verification. Read `references/limitations.md`.
