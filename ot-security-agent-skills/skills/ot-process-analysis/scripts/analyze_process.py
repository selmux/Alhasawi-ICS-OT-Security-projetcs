#!/usr/bin/env python3
"""Offline evidence-oriented OT process review. Python >=3.9; standard library only."""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

STAGES = ('command_observed','protocol_acknowledged','state_observed','physical_effect_correlated')
OPERATIONS = ('setpoint_write','coil_write','start','stop','alarm_change','interlock_override','communications_control','read','other')
RISKS = {
    'setpoint_write': 'May alter a controlled variable if accepted and applied; requires engineering scaling and telemetry to assess impact.',
    'coil_write': 'May change discrete output/state if accepted and interlocks permit.',
    'start': 'May start equipment if command is applied and permissives allow.',
    'stop': 'May stop equipment if command is applied and permissives allow.',
    'alarm_change': 'May change alarm visibility or response; verify configuration and events.',
    'interlock_override': 'May affect protective logic if override was applied; verify control logic and telemetry.',
    'communications_control': 'May interrupt monitoring/control communications if applied.',
}

class InputError(ValueError):
    pass

def analyze(document):
    if not isinstance(document, dict) or not isinstance(document.get('observations'), list):
        raise InputError('Expected JSON object with observations array')
    rows = document['observations']
    if len(rows) > 100000:
        raise InputError('Too many observations (max 100000)')
    findings=[]; by_asset=defaultdict(list); ids=set()
    for ix, r in enumerate(rows):
        if not isinstance(r, dict):
            raise InputError(f'Observation {ix}: expected object')
        for key in ('id','source','asset','target','operation','evidence_stage'):
            if not isinstance(r.get(key), str) or not r[key].strip():
                raise InputError(f'Observation {ix}: missing/invalid {key}')
        if r['id'] in ids:
            raise InputError(f'Duplicate observation id: {r["id"]}')
        ids.add(r['id'])
        if r['operation'] not in OPERATIONS:
            raise InputError(f'Observation {ix}: unsupported operation {r["operation"]}')
        if r['evidence_stage'] not in STAGES:
            raise InputError(f'Observation {ix}: unsupported stage {r["evidence_stage"]}')
        warnings=[]
        if r['operation'] in ('setpoint_write','coil_write') and 'value' not in r:
            warnings.append('No value supplied; cannot determine requested magnitude/state')
        if r['operation']=='setpoint_write' and not r.get('unit'):
            warnings.append('Units/scaling not established; do not interpret raw value as engineering quantity')
        if r['evidence_stage']=='command_observed':
            warnings.append('Command observation alone does not prove acceptance or physical effect')
        if r['evidence_stage']=='protocol_acknowledged':
            warnings.append('Protocol acknowledgement alone does not prove physical effect')
        finding={k:r[k] for k in ('id','source','asset','target','operation','evidence_stage')}
        for key in ('time_utc','protocol','actor','value','unit','note'):
            if key in r: finding[key]=r[key]
        finding['potential_risk']=RISKS.get(r['operation'])
        finding['limitations']=warnings
        findings.append(finding)
        by_asset[r['asset']].append(r['id'])
    return {
        'case_id':document.get('case_id'),
        'summary':{'observation_count':len(findings),'operations':dict(Counter(x['operation'] for x in findings)),
                   'evidence_stages':dict(Counter(x['evidence_stage'] for x in findings)),
                   'assets':{k:v for k,v in sorted(by_asset.items())}},
        'findings':findings,
        'methodology':'Offline analyst-labelled evidence; no protocol parsing, command execution, threshold inference or physical-impact verification performed.'
    }

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path,help='JSON evidence observations')
    p.add_argument('--output',type=Path,help='Optional JSON report path')
    args=p.parse_args(argv)
    try:
        doc=json.loads(args.input.read_text(encoding='utf-8'))
        out=analyze(doc)
    except (OSError,UnicodeError,json.JSONDecodeError,InputError) as e:
        print(f'Error: {e}',file=sys.stderr)
        return 2
    payload=json.dumps(out,indent=2,ensure_ascii=False)+'\n'
    if args.output: args.output.write_text(payload,encoding='utf-8')
    else: print(payload,end='')
    return 0

if __name__=='__main__':
    sys.exit(main())
