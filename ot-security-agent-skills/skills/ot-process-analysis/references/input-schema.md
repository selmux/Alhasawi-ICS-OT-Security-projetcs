# Input format (JSON)

```json
{
  "case_id": "training-case",
  "observations": [
    {
      "id": "o1",
      "time_utc": "2026-09-08T02:17:00Z",
      "source": "capture.pcap frame 413",
      "protocol": "Modbus TCP",
      "actor": "10.0.0.30",
      "asset": "PLC-1",
      "target": "holding_register:100",
      "operation": "setpoint_write",
      "value": 920,
      "unit": null,
      "evidence_stage": "command_observed",
      "note": "Raw register value; scaling not established"
    }
  ]
}
```

Required fields: `id`, `source`, `asset`, `target`, `operation`, `evidence_stage`. Optional fields: `time_utc`, `protocol`, `actor`, `value`, `unit`, `note`. Values are raw unless a supported engineering mapping is supplied. Allowed stages: `command_observed`, `protocol_acknowledged`, `state_observed`, `physical_effect_correlated`.

Supported operation labels include `setpoint_write`, `coil_write`, `start`, `stop`, `alarm_change`, `interlock_override`, `communications_control`, `read`, and `other`. These are analyst annotations, not inferred packet decodes. The script checks contradictions and reports limitations but cannot infer plant safety on its own.

## Evidence strength
`command_observed` = request visible; `protocol_acknowledged` = corresponding reply shows protocol-level acceptance; `state_observed` = independent device state/telemetry; `physical_effect_correlated` = measured effect correlated in time and causality assessed by analyst. These are increasing evidence categories, **not automatic conclusions**. A protocol ACK does not establish physical change.
