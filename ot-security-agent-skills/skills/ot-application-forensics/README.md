# OT Application Forensics Agent Skill (v0.1.0)

A portable, offline-only Python 3.9+ skill for forensic triage of Node-RED, Grafana, InfluxDB, and MariaDB textual exports. Uses Python standard library; compatible with Windows 11 PowerShell, Linux, and macOS.

## Windows 11

```powershell
cd .\ot-application-forensics
python -m unittest discover -s tests -v
python scripts\analyze_apps.py examples\sample-flow.json --output report.json
```

Analyze multiple files: `python scripts\analyze_apps.py flow.json dashboard.json dump.sql --output findings.json`.

This is **static artifact triage**, not an active scanner, full SQL parser, or PCAP decoder. Review `SKILL.md` and `references/artifacts.md` for evidence rules and limitations. Sensitive fields are redacted in reports.
