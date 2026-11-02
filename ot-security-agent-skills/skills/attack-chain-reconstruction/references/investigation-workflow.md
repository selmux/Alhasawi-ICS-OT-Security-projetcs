# Investigative workflow

1. Identify source formats and timezone settings; preserve raw evidence unchanged.
2. Normalize host identities (IP, hostnames, NAT translations, MAC, user account) without silently merging distinct entities.
3. Correlate entry (credentials, exploitation), privilege changes, discovery, pivots, server access, and OT command activity.
4. Separate command *request*, protocol *acknowledgment*, PLC *state*, and *physical impact* as different evidentiary assertions.
5. Maintain alternative hypotheses for ambiguous multi-party or periodic traffic.
6. Link events explicitly only when cross-source IDs, session tokens, 5-tuples, timestamps plus corroborating content, or other clear details justify it.
7. Document missing traffic, clock skew, packet loss, time-zone uncertainty, and parsing limits.
8. Write timeline and technical incident narrative with frame numbers/log line IDs. Use `flag-validator` for any CTF flag candidate.
