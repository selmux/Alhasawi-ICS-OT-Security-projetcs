#!/usr/bin/env python3
"""Read-only IEC 60870-5-104 PCAP triage. Stdlib; no live network access."""
import argparse,collections,datetime,json,pathlib,sys
from pcap_core import load,CaptureError
TYPEIDS={1:'M_SP_NA_1 single point',3:'M_DP_NA_1 double point',9:'M_ME_NA_1 normalized',11:'M_ME_NB_1 scaled',13:'M_ME_NC_1 short floating',30:'M_SP_TB_1 timestamped single point',31:'M_DP_TB_1 timestamped double point',34:'M_ME_TD_1 timestamped normalized',35:'M_ME_TE_1 timestamped scaled',36:'M_ME_TF_1 timestamped short floating',45:'C_SC_NA_1 single command',46:'C_DC_NA_1 double command',47:'C_RC_NA_1 regulating command',48:'C_SE_NA_1 normalized setpoint',49:'C_SE_NB_1 scaled setpoint',50:'C_SE_NC_1 floating setpoint',51:'C_BO_NA_1 bitstring command',58:'C_SC_TA_1 timestamped single command',59:'C_DC_TA_1 timestamped double command',60:'C_RC_TA_1 timestamped regulating command',61:'C_SE_TA_1 timestamped normalized setpoint',62:'C_SE_TB_1 timestamped scaled setpoint',63:'C_SE_TC_1 timestamped floating setpoint',64:'C_BO_TA_1 timestamped bitstring',100:'C_IC_NA_1 interrogation',101:'C_CI_NA_1 counter interrogation',103:'C_CS_NA_1 clock sync',104:'C_TS_NA_1 test',105:'C_RP_NA_1 reset process',107:'C_TS_TA_1 timestamped test'}
CONTROL=set(range(45,52))|set(range(58,65))|{100,101,103,105}
SIZES={1:1,3:1,9:3,11:3,13:5,30:8,31:8,34:10,35:10,36:12,45:1,46:1,47:1,48:3,49:3,50:5,51:4,58:8,59:8,60:8,61:10,62:10,63:12,64:11,100:1,101:1,103:7,104:2,105:1,107:9}
UFUNCTIONS={0x07:'STARTDT act',0x0b:'STARTDT con',0x13:'STOPDT act',0x23:'STOPDT con',0x43:'TESTFR act',0x83:'TESTFR con'}
def utc(x):return datetime.datetime.fromtimestamp(x,datetime.timezone.utc).isoformat() if x is not None else None
def parse_asdu(data):
    if len(data)<6:return {'warning':'Truncated ASDU','raw_hex':data.hex()}
    typ,vsq,c1,c2=data[:4];n=vsq&127;seq=bool(vsq&128);cause=c1&63;negative=bool(c1&64);test=bool(c1&128);originator=c2;ca=int.from_bytes(data[4:6],'little');remaining=data[6:]
    out={'type_id':typ,'type_name':TYPEIDS.get(typ,'Unknown'),'vsq_count':n,'sequential_ioa':seq,'cause_of_transmission':cause,'negative_confirmation':negative,'test_flag':test,'originator':originator,'common_address':ca,'information_objects':[],'asdu_body_hex':remaining.hex(),'control_command_candidate':typ in CONTROL}
    if typ not in SIZES:
        out['warning']='Unsupported variable-size information element; raw bytes preserved';return out
    size=SIZES[typ];position=0;first_ioa=None
    for i in range(n):
        if (i==0 or not seq):
            if position+3>len(remaining):out['warning']='Truncated information object address';break
            ioa=int.from_bytes(remaining[position:position+3],'little');position+=3
            if i==0:first_ioa=ioa
        else:ioa=first_ioa+i
        if position+size>len(remaining):out['warning']='Truncated information element';break
        val=remaining[position:position+size];position+=size
        obj={'ioa':ioa,'value_hex':val.hex()}
        if typ in (45,46,47,58,59,60):obj['select_before_operate']=bool(val[0]&0x80);obj['qualifier']=val[0]
        if typ in (48,49,50,61,62,63):
            q_index={48:2,49:2,50:4,61:2,62:2,63:4}[typ]
            obj['select_before_operate']=bool(val[q_index]&0x80)
        if typ in (1,3,30,31):obj['state']=val[0]&3
        out['information_objects'].append(obj)
    if position<len(remaining):out['trailing_hex']=remaining[position:].hex()
    return out

def parse_apdu(raw):
    if len(raw)<6 or raw[0]!=0x68:return None
    length=raw[1];out={'apdu_length':length,'complete':len(raw)>=length+2}
    if not out['complete'] or length<4:out['warning']='Truncated or invalid APCI';return out
    ctrl=raw[2:6];body=raw[6:2+length]
    if ctrl[0]&1==0:
        out.update(frame_type='I',send_seq=int.from_bytes(ctrl[:2],'little')>>1,recv_seq=int.from_bytes(ctrl[2:4],'little')>>1)
        out['asdu']=parse_asdu(body) if body else {'warning':'Missing ASDU'}
        out['control_command_candidate']=out['asdu'].get('control_command_candidate',False)
    elif ctrl[0]&3==1:out.update(frame_type='S',recv_seq=int.from_bytes(ctrl[2:4],'little')>>1)
    elif ctrl[0]&3==3:out.update(frame_type='U',u_function=UFUNCTIONS.get(ctrl[0],f'Unknown 0x{ctrl[0]:02x}'))
    else:out['warning']='Unknown APCI control format'
    return out

def scan_payload(payload):
    offset=0;events=[];issues=[]
    while offset<len(payload):
        if payload[offset]!=0x68:
            issues.append({'offset':offset,'reason':'Unexpected bytes or mid-APDU fragment'});break
        if offset+2>len(payload):issues.append({'offset':offset,'reason':'Incomplete APDU length'});break
        length=payload[offset+1]
        if length<4 or length>253:issues.append({'offset':offset,'reason':'Invalid APDU length'});break
        if offset+2+length>len(payload):issues.append({'offset':offset,'reason':'Split APDU; TCP reassembly required'});break
        item=parse_apdu(payload[offset:offset+2+length]);events.append({'segment_offset':offset,**item});offset+=length+2
    return events,issues

def analyze(paths,limit=100,max_packets=300000):
    result=[]
    for path in paths:
        packets=load(path,max_packets);events=[];warnings=[];candidates=[];port_packets=0
        for p in packets:
            if p.get('protocol')!='TCP' or 2404 not in (p.get('sport'),p.get('dport')) or not p.get('payload'):continue
            port_packets+=1;decoded,issues=scan_payload(p['payload'])
            for d in decoded:
                ev={'frame':p['frame'],'time_utc':utc(p['time']),'src':p['src'],'dst':p['dst'],'sport':p['sport'],'dport':p['dport'],**d};events.append(ev)
                if ev.get('control_command_candidate'):candidates.append(ev)
            warnings.extend({'frame':p['frame'],**issue} for issue in issues)
        result.append({'file':str(path),'packet_count':len(packets),'tcp_2404_payload_packets':port_packets,'decoded_apdus':len(events),'frame_type_counts':dict(collections.Counter(e.get('frame_type','Unknown') for e in events)),'asdu_type_counts':dict(collections.Counter(e['asdu']['type_name'] for e in events if 'asdu' in e)),'control_command_candidate_count':len(candidates),'control_command_candidates':candidates[:limit],'events':events[:limit],'parse_warnings':warnings[:50],'limitations':['Packet-local analysis, no TCP segment reassembly, retransmission de-duplication, or IP fragment reassembly','Information element support is selective; unknown Type IDs retain raw data','State-changing commands are candidates only; direction, COT, confirmation and process impact need contextual review','Requires standard IEC-104 APCI and common 2-byte common address / 3-byte IOA layout']})
    return {'skill':'iec104-forensics','version':'0.1.0','captures':result}
def main():
    ap=argparse.ArgumentParser(description='Read-only offline IEC-104 PCAP forensic triage')
    ap.add_argument('captures',nargs='+');ap.add_argument('--output');ap.add_argument('--limit',type=int,default=100);ap.add_argument('--max-packets',type=int,default=300000);a=ap.parse_args()
    try:res=analyze(a.captures,a.limit,a.max_packets)
    except (OSError,CaptureError) as e:sys.exit(f'Error: {e}')
    txt=json.dumps(res,indent=2)
    if a.output:pathlib.Path(a.output).write_text(txt+'\n',encoding='utf-8');print('Saved',a.output)
    else:print(txt)
if __name__=='__main__':main()
