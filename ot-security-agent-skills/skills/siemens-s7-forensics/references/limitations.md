# Known limits — v0.1.0

- Parses only complete TPKT records contained in a single TCP packet. Split and out-of-order segments are not reconstructed, and retransmissions can duplicate events.
- IPv4/IPv6 handling follows the shared packet reader; IPv6 extension headers and fragmented IP traffic are not reassembled.
- Connection setup COTP CR/CC packets are ignored as non-S7 PDUs.
- Userdata including detailed SZL semantics is not fully decoded; any `userdata_subfunction` needs Wireshark confirmation.
- No S7comm Plus, TIA Portal protected communications, or TLS decryption.
- Does not fully interpret Write Var data transport types, status codes per item, block downloads, or PLC runtime success.
- No active PLC connection, unauthenticated scanning, command injection, or device interaction.
