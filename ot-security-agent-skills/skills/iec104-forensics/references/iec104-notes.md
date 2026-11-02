# IEC-104 analysis notes

IEC-104 commonly uses TCP port 2404. Each APDU begins with 0x68, followed by one byte indicating APCI length; the 4-byte control field identifies I, S or U frame format.

- I-format: send and receive sequence numbers (15-bit, encoded shifted by one), followed by ASDU.
- S-format: receive sequence acknowledgment without ASDU.
- U-format: STARTDT, STOPDT or TESTFR operations.
- Typical ASDU: Type ID (1 byte), VSQ (1), Cause of Transmission (2), Common Address (2), information objects with 3-byte IOAs.
- VSQ top bit indicates sequential IOAs; lower seven bits specify object count.
- Type IDs 45–51 are untimestamped controls/setpoints. 58–64 are timestamped controls/setpoints.
- COT 6 means activation request, 7 activation confirmation, 10 activation termination. Verify direction, test and negative bits before interpretation.
- An observation of a command request alone does NOT prove successful execution or physical impact.
