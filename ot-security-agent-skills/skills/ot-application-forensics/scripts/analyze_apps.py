#!/usr/bin/env python3
"""Offline, read-only OT application artifact triage. Python 3.9+, stdlib only."""
import argparse, csv, hashlib, json, re, sys
from pathlib import Path
from datetime import datetime, timezone

MAX_BYTES=32*1024*1024
TOKEN_RE=re.compile(r'(?i)(password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|credential|authorization)')
URL_RE=re.compile(r'(?i)\b(?:https?|mqtt|tcp|modbus|opc\.tcp)://[^\s\"<>]+')
HOST_RE=re.compile(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b')
SQL_RE=re.compile(r'(?i)\b(?:CREATE\s+TABLE|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|GRANT\s+|SELECT\s+.+?\s+FROM)\b')

def sha256(raw): return hashlib.sha256(raw).hexdigest()
def emit(findings,kind,path,loc,detail,confidence='observed'):
    findings.append({'kind':kind,'file':str(path),'location':loc,'detail':detail,'evidence_level':confidence})
def redact(value):
    if isinstance(value,str):
        return '<redacted>' if value else '<empty>'
    return '<redacted>'
def inspect_json(obj,path,findings):
    # Recursive traversal maintains JSON-pointer paths, but never outputs sensitive values.
    def walk(value,ptr):
        if isinstance(value,dict):
            typ=str(value.get('type','')).lower()
            if typ in ('tab','inject','function','http request','http in','http response','mqtt in','mqtt out','tcp in','tcp out','modbus-read','modbus-write'):
                emit(findings,'nodered_node',path,ptr,{'type':typ,'id':value.get('id'),'name':value.get('name')})
            if 'panels' in value or ('dashboard' in value and isinstance(value.get('dashboard'),dict)):
                emit(findings,'grafana_dashboard',path,ptr,{'title':value.get('title') or value.get('dashboard',{}).get('title')})
            if value.get('type') in ('influxdb','mysql','prometheus','mssql','postgres') or ('datasource' in value and 'url' in value):
                emit(findings,'datasource',path,ptr,{'type':value.get('type'),'name':value.get('name')})
            for k,v in value.items():
                p=ptr+'/'+str(k).replace('~','~0').replace('/','~1')
                if TOKEN_RE.search(k):
                    emit(findings,'potential_secret_field',path,p,{'key':k,'value':redact(v)})
                if isinstance(v,str) and not TOKEN_RE.search(k):
                    for hit in URL_RE.findall(v)[:10]:
                        # User info and query parameters can contain credentials; do not expose raw URLs.
                        from urllib.parse import urlsplit
                        try:
                            u=urlsplit(hit); endpoint=f'{u.scheme}://{u.hostname or "?"}'+(f':{u.port}' if u.port else '')
                        except ValueError: endpoint='<malformed-url>'
                        emit(findings,'endpoint_reference',path,p,{'endpoint':endpoint})
                    if k in ('func','function','query','rawSql','sql','command','script'):
                        emit(findings,'code_or_query',path,p,{'field':k,'length':len(v),'sha256':sha256(v.encode())})
                walk(v,p)
        elif isinstance(value,list):
            for i,v in enumerate(value):walk(v,ptr+'/'+str(i))
    walk(obj,'')

def inspect_text(text,path,findings):
    for n,line in enumerate(text.splitlines(),1):
        line=line[:8192]
        if TOKEN_RE.search(line):
            emit(findings,'potential_secret_line',path,f'line:{n}',{'redacted':True,'line_sha256':sha256(line.encode())})
        if SQL_RE.search(line):
            stmt=re.match(r'^\s*(CREATE|INSERT|UPDATE|DELETE|SELECT|GRANT)\b',line,re.I)
            emit(findings,'sql_statement',path,f'line:{n}',{'operation':stmt.group(1).upper() if stmt else 'SQL','line_sha256':sha256(line.encode())})
        if line.startswith('#') and ('influx' in str(path).lower()):continue
        if re.match(r'^[A-Za-z_:][\w.:-]*(?:,[^ ]+)?\s+[^ ]+\s+\d{10,19}\s*$',line):
            emit(findings,'influx_line_protocol',path,f'line:{n}',{'measurement':line.split(',')[0].split(' ')[0],'line_sha256':sha256(line.encode())})

def inspect_file(path):
    if not path.is_file():raise ValueError('not a file')
    if path.stat().st_size>MAX_BYTES:raise ValueError(f'file exceeds {MAX_BYTES} byte limit')
    raw=path.read_bytes(); findings=[]; errors=[]
    text=raw.decode('utf-8',errors='replace')
    if path.suffix.lower() in ('.json','.jsonl'):
        try:
            if path.suffix.lower()=='.jsonl':
                for i,line in enumerate(text.splitlines(),1):
                    if not line.strip():continue
                    try:inspect_json(json.loads(line),path,findings)
                    except json.JSONDecodeError as e:errors.append(f'JSONL line {i}: {e.msg}')
            else:inspect_json(json.loads(text),path,findings)
        except json.JSONDecodeError as e:errors.append(f'invalid JSON: {e.msg}')
    inspect_text(text,path,findings)
    return {'file':str(path),'size':len(raw),'sha256':sha256(raw),'findings':findings,'warnings':errors}

def main(argv=None):
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('files',nargs='+',help='Offline Node-RED/Grafana/InfluxDB/MariaDB exports or logs')
    a.add_argument('--output',help='JSON output file (stdout otherwise)')
    args=a.parse_args(argv); results=[]; had_error=False
    for name in args.files:
        p=Path(name)
        try:results.append(inspect_file(p))
        except (OSError,ValueError) as e:
            results.append({'file':str(p),'error':str(e)});had_error=True
    report={'skill':'ot-application-forensics','version':'0.1.0','generated_utc':datetime.now(timezone.utc).isoformat(),'files':results,'summary':{'files':len(results),'findings':sum(len(x.get('findings',[])) for x in results)},'limitations':['Heuristic offline artifact analysis; does not prove exploitability, compromise, or command execution','Raw PCAP and database binary formats require separate forensic tools','Secrets are redacted by default; URLs omit paths, usernames and query parameters']}
    output=json.dumps(report,indent=2,ensure_ascii=False)
    if args.output:Path(args.output).write_text(output+'\n',encoding='utf-8')
    else:print(output)
    return 1 if had_error else 0
if __name__=='__main__':sys.exit(main())
