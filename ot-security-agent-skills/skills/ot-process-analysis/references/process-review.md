# Analyst review guide

## Questions to ask
- Is the endpoint an operator workstation, historian, engineering station, or unknown host? What evidence establishes role?
- Was the command accepted or rejected? Is there a correlated response or a later independent readback?
- What is the measurement scale, engineering unit, endianness and register/object mapping?
- Did a sensor show the commanded effect, and are there plausible alternative explanations?
- Were alarms, overrides, interlocks, or operator actions present before or after the command?
- Are plant operating limits provided by authoritative site documentation?

## Typical risk pathways (not proof of impact)
- Setpoint changes may change dosing, pressure, temperature or flow *if* applied by the control logic.
- Coil writes/start/stop requests may change equipment state *if* accepted and interlocks permit.
- Alarm changes may reduce operator visibility *if* they disable/alter monitoring.
- Communication-control requests may inhibit monitoring *if* a controller applies them.

Use conditional language until independently corroborated. Never assign real-world health or safety effects from raw register values alone.
