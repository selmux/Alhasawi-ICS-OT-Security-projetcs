# Decoder guidance

BACnet/IP commonly uses UDP 47808 (0xBAC0). Standard BVLC payloads start with `81`; a BVLC header is followed by an NPDU (protocol version usually 1), then an APDU. Port-based selection alone does not authenticate a BACnet endpoint.

Confirmed BACnet service choices: `readProperty (12)`, `readPropertyMultiple (14)`, `writeProperty (15)`, `writePropertyMultiple (16)`, `deviceCommunicationControl (17)`, `reinitializeDevice (20)`.

A state-changing service is a candidate for review, not automatically an attack. Interpret BACnet context tags cautiously: nested tags, constructed types, segmentation, vendor extensions and routed networks can defeat a simplified parser.

No payload data is sent to any external endpoint. Inspect the raw capture with Wireshark for complex APDUs, acknowledgement matching and retransmissions.
