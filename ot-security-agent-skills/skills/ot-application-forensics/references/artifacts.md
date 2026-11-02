# Supported evidence and interpretation

| Artifact | Indicators | What it cannot prove alone |
| --- | --- | --- |
| Node-RED flows JSON | `type`, `id`, `func`, HTTP/MQTT and Modbus connector references | That a flow deployed or ran |
| Grafana dashboards JSON | panels, queries, datasource references | Actual execution of dashboard queries |
| Grafana datasource exports | backend type, endpoint, secret-field presence | Valid credentials or successful connections |
| InfluxDB line protocol | measurements, tags, fields, timestamps | Device origin or integrity without corroboration |
| MariaDB SQL dumps and textual logs | DDL/DML references, grants, potential credentials | That a dump statement ran on the live server |

Preserve source hashes and precise artifact locations. Exported configurations are not packet-level observations. For a real-time timeline, use matching PCAP request/response traffic and application audit logs. The scanner redacts sensitive fields. Data from an industrial HMI may have process implications; use `ot-process-analysis` only after establishing command intent, observed responses, and telemetry.
