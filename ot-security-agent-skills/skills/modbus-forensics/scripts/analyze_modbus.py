#!/usr/bin/env python3
"""Offline Modbus/TCP forensic triage. No network activity; Python stdlib only.
Note: parsers operate on individual TCP payloads. Split PDUs require full TCP reassembly.
"""
import argparse, collections, datetime, json, pathlib, sys
from pcap_core import load, CaptureError

FUNCS={1:'Read Coils',2:'Read Discrete Inputs',3:'Read Holding Registers',4:'Read Input Registers',5:'Write Single Coil',6:'Write Single Register',15:'Write Multiple Coils',16:'Write Multiple Registers',22:'Mask Write Register',23:'Read/Write Multiple Registers',43:'Encapsulated Interface Transport'}
WRITE={5,6,15,16,22,23}

def u16(b): return int.from_bytes(b,'big')
def timestamp(t): return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat() if t is not None else None

def parse_pdu(pdu, response):
    if not pdu: return None
    fc=pdu[0]; base=fc&0x7f; data=pdu[1:]; result={'function':base,'function_name':FUNCS.get(base,'Unknown'),'is_exception':bool(fc&0x80),'raw_data_hex':data.hex()}
    if fc&0x80:
        if data: result['exception_code']=data[0]
        return result
    if not response:
        if base in (1,2,3,4,5,6,15,16,22,23) and len(data)>=4:
            result['address']=u16(data[0:2]);result['value_or_quantity']=u16(data[2:4])
            if base in (1,2,3,4,15,16):result['quantity']=u16(data[2:4])
            if base in (5,6):result['value']=u16(data[2:4])
            if base in (15,16) and len(data)>=5:
                count=data[4];result['byte_count']=count
                result['data_hex']=data[5:5+count].hex()
                result['payload_complete']=len(data)>=5+count
            if base==22 and len(data)>=6: result['and_mask']=u16(data[2:4]);result['or_mask']=u16(data[4:6])
            if base==23 and len(data)>=9:
                result.update(read_address=u16(data[0:2]),read_quantity=u16(data[2:4]),write_address=u16(data[4:6]),write_quantity=u16(data[6:8]),byte_count=data[8],data_hex=data[9:9+data[8]].hex())
    else:
        if base in (1,2,3,4,23) and data:
            result['byte_count']=data[0];result['data_hex']=data[1:1+data[0]].hex();result['payload_complete']=len(data)>=1+data[0]
            if base in (3,4,23) and result['payload_complete'] and data[0]%2==0:
                result['register_values']=[u16(data[i:i+2]) for i in range(1,1+data[0],2)]
        if base in (5,6,15,16) and len(data)>=4:
            result['address']=u16(data[:2]);result['value_or_quantity']=u16(data[2:4])
    return result

def pdus(payload):
    pos=0;out=[];errors=[]
    while pos+7<=len(payload):
        tid=u16(payload[pos:pos+2]); proto=u16(payload[pos+2:pos+4]);size=u16(payload[pos+4:pos+6])
        if proto!=0 or size<2 or size>260:
            errors.append({'offset':pos,'reason':'invalid MBAP header'});break
        end=pos+6+size
        if end>len(payload):
            errors.append({'offset':pos,'reason':'truncated PDU; TCP reassembly needed'});break
        uid=payload[pos+6]; body=payload[pos+7:end]
        out.append((tid,uid,body));pos=end
    if pos<len(payload) and len(payload)-pos<7:errors.append({'offset':pos,'reason':'trailing bytes or incomplete MBAP header'})
    return out,errors

def analyze(path, max_packets=300000, limit=100):
    packets=load(path,max_packets)
    events=[];errors=[];tcp_candidates=0
    for p in packets:
        if p.get('protocol')!='TCP' or 502 not in (p.get('sport'),p.get('dport')) or not p.get('payload'):continue
        tcp_candidates+=1
        response=p['sport']==502 and p['dport']!=502
        for tid,uid,body in pdus(p['payload'])[0]:
            d=parse_pdu(body,response)
            if not d:continue
            event={'frame':p['frame'],'time_utc':timestamp(p['time']),'src':p['src'],'dst':p['dst'],'sport':p['sport'],'dport':p['dport'],'direction':'response' if response else 'request','transaction_id':tid,'unit_id':uid,**d}
            event['write_candidate']=not response and d['function'] in WRITE and not d['is_exception']
            events.append(event)
        _,bad=pdus(p['payload'])
        if bad:
            errors.extend({'frame':p['frame'],**x} for x in bad)
    counts=collections.Counter((x['function'],x['function_name']) for x in events)
    writes=[e for e in events if e['write_candidate']]
    pairs=collections.Counter((e['src'],e['dst']) for e in events if e['direction']=='request')
    return {'file':str(path),'packet_count':len(packets),'tcp_port_502_payload_packets':tcp_candidates,'decoded_pdus':len(events),'function_counts':[{'function':f,'name':n,'count':v} for (f,n),v in sorted(counts.items())],'request_routes':[{'src':a,'dst':b,'count':v} for (a,b),v in pairs.most_common()],'write_candidate_count':len(writes),'write_candidates':writes[:limit],'events':events[:limit],'parser_warnings':errors[:50],'limitations':['TCP payload segmentation/retransmission not fully reconstructed; verify any missing or duplicate PDUs with TShark/Wireshark','Function code identifies request semantics, not proof of unauthorized access or physical effect','Writes are not automatically malicious.']}

def main():
    a=argparse.ArgumentParser(description='Read-only Modbus/TCP analysis of PCAP or PCAPNG')
    a.add_argument('capture');a.add_argument('--output',help='Write report to JSON file');a.add_argument('--max-packets',type=int,default=300000);a.add_argument('--limit',type=int,default=100,help='Maximum event/write records in report')
    args=a.parse_args()
    try:r=analyze(args.capture,args.max_packets,args.limit)
    except (OSError,CaptureError) as exc:raise SystemExit(f'Error: {exc}')
    output=json.dumps(r,indent=2)
    if args.output:pathlib.Path(args.output).write_text(output+'\n',encoding='utf-8');print(f'Saved {args.output}')
    else:print(output)
if __name__=='__main__':main()
