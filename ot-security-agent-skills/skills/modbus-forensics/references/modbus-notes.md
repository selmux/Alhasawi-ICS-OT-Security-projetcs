# Modbus TCP forensic notes

- Modbus TCP usually uses TCP port 502; do not assume every connection on that port is valid Modbus.
- MBAP header: transaction ID (2 bytes), protocol ID (2 bytes, zero), length (2 bytes), unit ID (1 byte); length counts unit ID plus PDU bytes.
- Common function codes: 1 read coils; 2 read discrete inputs; 3 read holding registers; 4 read input registers; 5 write single coil; 6 write single register; 15 write multiple coils; 16 write multiple registers; 22 mask write register; 23 read/write multiple registers.
- Exception responses set function high bit (e.g., 0x83) and carry an exception code.
- Network register/coil offsets are zero-based; labels such as 40001 are device/HMI convention, not encoded in the PDU.
- For function 5, 0xFF00 means ON, 0x0000 means OFF in compliant implementations.
- Modbus registers are 16-bit big-endian on wire. 32-bit numbers, floats, strings and word order are device-specific.
- Function 15 coil bits are packed least-significant-bit first within each byte.
- Match transaction IDs within the same TCP connection when correlating request/response; IDs alone may repeat.
- TCP may fragment or combine Modbus ADUs, retransmit bytes, or carry out-of-order segments. Reassembly and retransmission de-duplication must be verified before any completeness claim.
