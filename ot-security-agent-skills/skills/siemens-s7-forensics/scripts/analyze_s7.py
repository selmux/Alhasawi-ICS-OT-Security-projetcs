#!/usr/bin/env python3
"""Read-only, best-effort offline S7comm parser. Python standard library only."""
import argparse,collections,datetime,json,pathlib,sys
from pcap_core import load,CaptureError
ROSCTR={1:'Job',2:'Ack',3:'Ack_Data',7:'Userdata'}
FUNCTIONS={0x04:'Read Var',0x05:'Write Var',0x1a:'Request Download',0x1b:'Download Block',0x1c:'Download Ended',0x1d:'Start Upload',0x1e:'Upload',0x1f:'End Upload',0x28:'PLC Control',0x29:'PLC Stop',0xf0:'Setup Communication'}
AREAS={0x81:'Inputs',0x82:'Outputs',0x83:'Flags/Merkers',0x84:'Data Block',0x85:'Instance Data Block',0x1c:'Counters',0x1d:'Timers'}
def be16(b):return int.from_bytes(b,'big')
def utc(t):return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat() if t is not None else None
def parse_var_items(param):
    items=[]; warnings=[]
    if len(param)<2:return items,warnings
    n=param[1]; pos=2
    for idx in range(min(n,128)):
        if pos+2>len(param):warnings.append('Incomplete item header');break
        start=pos; kind=param[pos];length=param[pos+1]
        if length<2 or pos+2+length>len(param):warnings.append('Incomplete or invalid item length');break
        raw=param[pos:pos+2+length];item={'index':idx,'syntax_id':raw[2] if len(raw)>2 else None,'raw_hex':raw.hex()}
        if kind==0x12 and length>=10 and raw[2]==0x10:
            address=int.from_bytes(raw[9:12],'big');item.update(transport_size=raw[3],quantity=be16(raw[4:6]),db_number=be16(raw[6:8]),area_code=raw[8],area=AREAS.get(raw[8],'Unknown'),address_bits=address,address_byte=address//8,address_bit=address%8)
        items.append(item);pos=start+2+length
    return items,warnings
def parse_s7(blob):
    if len(blob)<10 or blob[0]!=0x32:return None
    ros=blob[1]; hlen=12 if ros in (2,3) else 10
    if len(blob)<hlen:return {'warning':'Truncated S7 header','raw_hex':blob.hex()}
    plen=be16(blob[6:8]);dlen=be16(blob[8:10]);expected=hlen+plen+dlen
    out={'rosctr':ros,'rosctr_name':ROSCTR.get(ros,'Unknown'),'pdu_reference':be16(blob[4:6]),'parameter_length':plen,'data_length':dlen,'complete':len(blob)>=expected}
    if ros in (2,3):out['error_class']=blob[10];out['error_code']=blob[11]
    if not out['complete']:
        out['warning']='Incomplete S7 PDU; TCP reassembly or capture verification required';return out
    param=blob[hlen:hlen+plen];data=blob[hlen+plen:expected]
    out['parameter_hex']=param.hex();out['data_hex']=data.hex()
    if param:
        fn=param[0];out['function_code']=fn;out['function_name']=FUNCTIONS.get(fn,'Unknown / user-data specific') if ros!=7 else 'Userdata'
        if ros!=7 and fn in (4,5):
            out['item_count']=param[1] if len(param)>1 else None
            if ros==1:
                out['items'],warnings=parse_var_items(param)
                if warnings:out['item_warnings']=warnings
                if fn==5:out['state_change_candidate']=True
        if ros==1 and fn in (0x28,0x29,0x1a,0x1b,0x1c):out['state_change_candidate']=True
        if ros==7 and len(param)>=8:
            out['userdata_type_group']=param[5];out['userdata_subfunction']=param[6]
            # SZL ID may appear in request/response data; do not infer solely from matching hex.
    return out
def decode_tpkt(payload):
    pos=0;out=[];warnings=[]
    while pos<len(payload):
        if len(payload)-pos<4:
            warnings.append({'offset':pos,'reason':'Incomplete TPKT header'});break
        if payload[pos]!=3 or payload[pos+1]!=0:
            # COTP connect/setup or non-TPKT bytes, not malformed S7 by itself
            warnings.append({'offset':pos,'reason':'Not TPKT v3'});break
        length=be16(payload[pos+2:pos+4])
        if length<7 or length>65535:
            warnings.append({'offset':pos,'reason':'Invalid TPKT length'});break
        if pos+length>len(payload):warnings.append({'offset':pos,'reason':'Split TPKT; TCP reassembly required'});break
        tpkt=payload[pos:pos+length];cotplen=tpkt[4]
        if 5+cotplen>len(tpkt):warnings.append({'offset':pos,'reason':'Invalid COTP header'});break
        cotp=tpkt[5:5+cotplen];app=tpkt[5+cotplen:]
        if app.startswith(b'\x32'):
            item=parse_s7(app)
            if item:out.append(item)
        pos+=length
    return out,warnings
def analyze(paths,max_packets=300000,limit=100):
    allreports=[]
    for path in paths:
        packets=load(path,max_packets);events=[];warnings=[];port_packets=0
        for p in packets:
            if p.get('protocol')!='TCP' or 102 not in (p.get('sport'),p.get('dport')) or not p.get('payload'):continue
            port_packets+=1
            parsed,issues=decode_tpkt(p['payload'])
            for a in parsed:
                events.append({'frame':p['frame'],'time_utc':utc(p['time']),'src':p['src'],'dst':p['dst'],'sport':p['sport'],'dport':p['dport'],**a})
            warnings.extend({'frame':p['frame'],**w} for w in issues)
        funcs=collections.Counter(e.get('function_name','Unknown') for e in events)
        changes=[e for e in events if e.get('state_change_candidate')]
        allreports.append({'file':str(path),'packet_count':len(packets),'tcp_102_payload_packets':port_packets,'decoded_s7_pdus':len(events),'function_counts':dict(funcs),'state_change_candidate_count':len(changes),'state_change_candidates':changes[:limit],'events':events[:limit],'parser_warnings':warnings[:40], 'limitations':['Packet-local parsing: TCP segmentation, retransmission deduplication, and IP fragmentation are not reconstructed','S7comm Plus, encrypted traffic, advanced user-data/SZL structures and response-item values are not fully decoded','Port 102 alone is not proof of S7comm; events require TPKT/COTP/S7 signature','State-changing commands are candidates, not proof of unauthorized access or physical effect']})
    return {'skill':'siemens-s7-forensics','version':'0.1.0','captures':allreports}
def main():
    ap=argparse.ArgumentParser(description='Offline Siemens S7comm forensic triage (no live network operations)')
    ap.add_argument('captures',nargs='+');ap.add_argument('--output');ap.add_argument('--max-packets',type=int,default=300000);ap.add_argument('--limit',type=int,default=100)
    a=ap.parse_args()
    try:res=analyze(a.captures,a.max_packets,a.limit)
    except (OSError,CaptureError) as exc:sys.exit(f'Error: {exc}')
    j=json.dumps(res,indent=2)
    if a.output:pathlib.Path(a.output).write_text(j+'\n',encoding='utf-8');print('Saved',a.output)
    else:print(j)
if __name__=='__main__':main()
