#!/usr/bin/env python3
"""Offline, conservative conversion of supported OT forensic JSON reports."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

SUPPORTED = {'modbus-forensics', 'bacnet-forensics', 'siemens-s7-forensics', 'iec104-forensics', 'ot-application-forensics', 'generic-events'}

def utc(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    if isinstance(value, str):
        try:
            x=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
            if x.tzinfo is None: return None
            return x.astimezone(dt.timezone.utc).isoformat().replace('+00:00','Z')
        except ValueError: return None
    return None

def source_loc(source, event, index):
    e={'source': str(source)}
    if isinstance(event.get('frame'), int) and event['frame']>0: e['frame']=event['frame']
    elif isinstance(event.get('line'), int) and event['line']>0: e['line']=event['line']
    else: e['record']=index
    return e

def load_inputs(paths):
    for path in paths:
        p=Path(path); raw=p.read_bytes()
        data=json.loads(raw)
        if not isinstance(data, (dict,list)): raise ValueError(f'{p}: root must be object or array')
        yield p,data,hashlib.sha256(raw).hexdigest()

def detect(d):
    if isinstance(d,list) or (isinstance(d,dict) and 'events' in d and not 'decoded_pdus' in d):
        return 'generic-events'
    if not isinstance(d,dict): return None
    if d.get('skill')=='siemens-s7-forensics' or 'decoded_s7_pdus' in d:return 'siemens-s7-forensics'
    if d.get('skill')=='iec104-forensics' or 'decoded_apdus' in d:return 'iec104-forensics'
    if 'bacnet_packets' in d or 'state_change_candidates' in d and 'capture' in d:return 'bacnet-forensics'
    if 'decoded_pdus' in d and 'write_candidates' in d:return 'modbus-forensics'
    if 'findings' in d and 'sha256' in d:return 'ot-application-forensics'
    return None

def series(kind, document):
    if kind in ('siemens-s7-forensics','iec104-forensics'):
        for capture in document.get('captures',[]):
            if isinstance(capture,dict):yield capture.get('file','unknown-capture'),capture.get('events',[])
    elif kind=='bacnet-forensics':
        events=document.get('sample_events',[])
        extras=document.get('state_change_candidates',[])
        yield document.get('capture','unknown-capture'),dedup(events,extras)
    elif kind=='modbus-forensics':
        yield document.get('file','unknown-capture'),dedup(document.get('events',[]),document.get('write_candidates',[]))
    elif kind=='ot-application-forensics':
        yield document.get('file','unknown-artifact'),document.get('findings',[])
    else:yield 'input-json',document if isinstance(document,list) else document.get('events',[])

def dedup(*groups):
    seen=set();out=[]
    for group in groups:
        if not isinstance(group,list):continue
        for event in group:
            if not isinstance(event,dict):continue
            key=json.dumps(event,sort_keys=True,default=str)
            if key not in seen:seen.add(key);out.append(event)
    return out

def classify(kind,e):
    """Returns neutral action, optional annotated process operation, and note."""
    if kind=='modbus-forensics':
        fn=e.get('function');direction=e.get('direction','unknown')
        action=f'Modbus function {fn} {direction}'
        op=None
        if direction=='request' and e.get('write_candidate'):
            op='coil_write' if fn in (5,15) else 'setpoint_write' if fn in (6,16) else 'other'
        return action,op,'Modbus write candidate; value-to-process mapping not established'
    if kind=='bacnet-forensics':
        srv=e.get('service','unknown')
        op='communications_control' if e.get('kind')=='confirmed-request' and e.get('service_id')==17 else 'other' if e.get('kind')=='confirmed-request' and e.get('service_id') in (10,11,15,16,20) else None
        return f'BACnet {srv} ({e.get("kind","unknown")})',op,'BACnet state-change candidate; no verified physical impact'
    if kind=='siemens-s7-forensics':
        op='other' if e.get('state_change_candidate') else None
        return f'S7comm {e.get("function_name","unknown function")}',op,'S7 state-change candidate requires command/response review'
    if kind=='iec104-forensics':
        asdu=e.get('asdu') if isinstance(e.get('asdu'),dict) else {}
        op='setpoint_write' if e.get('control_command_candidate') and asdu.get('type_id') in (48,49,50,61,62,63) else 'other' if e.get('control_command_candidate') else None
        return f'IEC-104 {asdu.get("type_name", e.get("frame_type","frame"))}',op,'IEC-104 control candidate requires COT and response review'
    if kind=='ot-application-forensics':
        return f'Application artifact finding: {e.get("type",e.get("kind","observation"))}',None,'Configuration observation; execution not established'
    return str(e.get('action','Generic structured event')),None,'Source supplied structured event'

def normalize(paths, keep_all=False):
    timeline=[];observations=[];warnings=[];inputs=[];counter=0
    for p,d,sha in load_inputs(paths):
        kind=detect(d);inputs.append({'file':str(p),'sha256':sha,'detected_type':kind})
        if kind is None:
            warnings.append(f'{p}: unsupported schema, skipped');continue
        for src,events in series(kind,d):
            if not isinstance(events,list):warnings.append(f'{p}: events not an array');continue
            for index,e in enumerate(events,1):
                if not isinstance(e,dict):warnings.append(f'{p}: record {index} not an object');continue
                stamp=utc(e.get('time_utc',e.get('utc',e.get('timestamp',e.get('time')))))
                if not stamp:
                    warnings.append(f'{p}: record {index} missing valid timezone-aware timestamp; skipped');continue
                counter+=1; eid=f'evt-{counter:06d}'
                action,op,note=classify(kind,e)
                loc=source_loc(src if src!='input-json' else p,e,index)
                evidence=[loc]
                if kind=='generic-events' and isinstance(e.get('evidence'),list) and e['evidence']:
                    supplied=[x for x in e['evidence'] if isinstance(x,dict) and x.get('source') and any(k in x for k in ('frame','line','record','detail'))]
                    if supplied:evidence=supplied
                details={'input_report':str(p),'source_kind':kind,'normalization_note':note,'source_record_number':index}
                item={'id':eid,'timestamp':stamp,'action':action,'evidence':evidence,'stage':'other','confidence':'observed','details':details}
                srcip=e.get('src',e.get('source_ip'))
                dstip=e.get('dst',e.get('destination_ip'))
                if srcip:item['source_ip']=srcip
                if dstip:item['destination_ip']=dstip
                item['protocol']={'modbus-forensics':'Modbus TCP','bacnet-forensics':'BACnet/IP','siemens-s7-forensics':'S7comm','iec104-forensics':'IEC-104','ot-application-forensics':'application artifact','generic-events':e.get('protocol','unknown')}[kind]
                if kind=='generic-events' and isinstance(e.get('stage'),str):item['stage']=e['stage']
                timeline.append(item)
                if op:
                    if kind=='modbus-forensics':target=f'register_or_coil:{e.get("address","unknown")}'
                    elif kind=='bacnet-forensics':target=f'BACnet object:{e.get("object_id","unknown")}'
                    elif kind=='iec104-forensics':target='IEC-104 IOA:see original ASDU'
                    else:target='unspecified target'
                    observations.append({'id':eid,'time_utc':stamp,'source':f'{loc["source"]} {next((str(k)+" "+str(v) for k,v in loc.items() if k!="source"), "")}', 'protocol':item['protocol'],'actor':srcip or 'unknown','asset':dstip or 'unknown','target':target,'operation':op,'evidence_stage':'command_observed','note':note+'; unverified semantics and authorization'})
    timeline.sort(key=lambda x:(x['timestamp'],x['id']))
    observations.sort(key=lambda x:(x['time_utc'],x['id']))
    return {'schema_version':'0.1','generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'inputs':inputs,'events_written':len(timeline),'observations_written':len(observations),'warnings':warnings,'limitations':['Only exported/sampled records are normalized; upstream report event limits may omit evidence','Output mappings are conservative and do not establish process semantics or causality','Hashes cover input JSON files; source capture hashes require independent collection']}, {'events':timeline}, {'case_id':'normalized-ot-evidence','observations':observations}

def main():
    ap=argparse.ArgumentParser(description='Normalize offline OT forensic JSON into downstream skill schemas')
    ap.add_argument('reports',nargs='+',help='JSON output from supported forensic analyzers')
    ap.add_argument('--output-dir',required=True,help='Directory for normalized JSON outputs')
    args=ap.parse_args()
    try: summary,chain,process=normalize(args.reports)
    except (OSError,ValueError,json.JSONDecodeError) as exc:ap.error(str(exc))
    out=Path(args.output_dir);out.mkdir(parents=True,exist_ok=True)
    for name,value in [('normalization-summary.json',summary),('attack-chain-events.json',chain),('process-observations.json',process)]:
        (out/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'output_dir':str(out),'events':summary['events_written'],'process_observations':summary['observations_written'],'warnings':len(summary['warnings'])},indent=2))
if __name__=='__main__':main()
