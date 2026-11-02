# Parser limitations

- No TCP stream reassembly, retransmission removal, IPv4 fragment reassembly, or IPv6 extension parsing.
- Recognizes traffic on TCP/2404; alternate ports require PCAP preprocessing or future enhancements.
- Selectively decodes common fixed-size information object structures. Unknown ASDU types preserve raw bytes.
- IEC-104 telemetry quality descriptors, CP56Time2a timestamps, and analog values are not fully interpreted.
- Port 2404 alone is not proof of IEC-104. Header validation is used.
- A control command is not proof of malicious activity, response success, or process effect.
- Validate with Wireshark/TShark for operational or high-stakes interpretation.
