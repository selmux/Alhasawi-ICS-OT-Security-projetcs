# S7comm quick reference

- ISO-on-TCP commonly runs on TCP 102. TCP port alone is a candidate, not confirmation.
- TPKT version 3, length field big-endian; COTP Data TPDU commonly begins `02 f0 80`.
- Classic S7comm starts with `0x32`, followed by ROSCTR (1=Job, 2=Ack, 3=Ack_Data, 7=Userdata), S7 PDU reference, parameter length and data length.
- Standard job functions: `0x04` Read Var; `0x05` Write Var; `0x1a` Request Download; `0x1b` Download Block; `0x1c` Download Ended; `0x1d` Start Upload; `0x1e` Upload; `0x1f` End Upload; `0x28` PLC Control; `0x29` PLC Stop; `0xf0` Setup Communication.
- A classic S7ANY variable specification commonly encodes syntax 0x10, transport size, element count, DB number, memory area, and a 24-bit *bit-address*; divide by 8 for byte address.
- Area `0x81` Inputs, `0x82` Outputs, `0x83` Flags/Merkers, `0x84` DB, `0x85` Instance DB, `0x1c` Counters, `0x1d` Timers.
- Responses contain status/error codes; don't infer successful manipulation from a request alone.
- Encoded numeric and character values require type and byte-order validation. IEEE-754 single precision values require 4 bytes.
