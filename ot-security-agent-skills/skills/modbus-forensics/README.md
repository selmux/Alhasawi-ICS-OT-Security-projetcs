# modbus-forensics — Skill #2

Portable, read-only Modbus/TCP forensic agent skill for PCAP and PCAPNG captures.

## Installation
Unzip into your agent skill directory, for example `%USERPROFILE%\.agents\skills\modbus-forensics`.
No Python packages required (stdlib-only). Python 3.9+ recommended.

## Run
`python scripts\analyze_modbus.py "C:\path\sample.pcap" --output report.json`

## Test
`python -m unittest discover -s tests -v`

## Limits
The bundled parser handles complete Modbus ADUs contained within individual TCP segments; it is not a full TCP reassembly engine. Inspect warnings and verify segmented streams using Wireshark/TShark. Results are evidentiary candidates, not proof of malice or process impact.
