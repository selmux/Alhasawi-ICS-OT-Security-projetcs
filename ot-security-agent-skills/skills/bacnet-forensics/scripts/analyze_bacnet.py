#!/usr/bin/env python3
"""Offline BACnet/IP triage: stdlib only; PCAP/PCAPNG Ethernet IPv4 UDP."""
import argparse, collections, datetime, json, socket, struct, pathlib
SERVICES={0:'acknowledgeAlarm',1:'confirmedCOVNotification',2:'confirmedEventNotification',3:'getAlarmSummary',4:'getEnrollmentSummary',5:'subscribeCOV',6:'atomicReadFile',7:'atomicWriteFile',8:'addListElement',9:'removeListElement',10:'createObject',11:'deleteObject',12:'readProperty',13:'readPropertyConditional',14:'readPropertyMultiple',15:'writeProperty',16:'writePropertyMultiple',17:'deviceCommunicationControl',18:'confirmedPrivateTransfer',19:'confirmedTextMessage',20:'reinitializeDevice',21:'vtOpen',22:'vtClose',23:'vtData',24:'authenticate',25:'requestKey',26:'readRange',27:'lifeSafetyOperation',28:'subscribeCOVProperty',29:'getEventInformation',30:'subscribeCOVPropertyMultiple',31:'confirmedCOVNotificationMultiple'}
UNCONFIRMED={0:'iAm',1:'iHave',2:'unconfirmedCOVNotification',3:'unconfirmedEventNotification',4:'unconfirmedPrivateTransfer',5:'unconfirmedTextMessage',6:'timeSynchronization',7:'whoHas',8:'whoIs',9:'utcTimeSynchronization',10:'writeGroup',11:'unconfirmedCOVNotificationMultiple'}
OBJECTS={0:'analogInput',1:'analogOutput',2:'analogValue',3:'binaryInput',4:'binaryOutput',5:'binaryValue',8:'device',13:'multiStateInput',14:'multiStateOutput',19:'multiStateValue',20:'trendLog',30:'accessDoor'}
PROPERTIES={75:'objectIdentifier',77:'objectName',85:'presentValue',87:'priorityArray',111:'statusFlags',112:'systemStatus'}

def packets(path):
    raw=pathlib.Path(path).read_bytes()
    if raw[:4] in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'):
        little=raw[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'); nano=raw[:4] in (b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d');fmt='<' if little else '>'
        network=struct.unpack_from(fmt+'I',raw,20)[0]&0xffff;off=24;n=0
        while off+16<=len(raw):
            sec,sub,cap,_=struct.unpack_from(fmt+'IIII',raw,off);off+=16
            if off+cap>len(raw):break
            n+=1;yield n,sec+sub/(1e9 if nano else 1e6),network,raw[off:off+cap];off+=cap
    elif raw[:4]==b'\x0a\x0d\x0d\x0a':
        off=0;n=0;fmt='<';interfaces=[]
        while off+12<=len(raw):
            if raw[off:off+4]==b'\x0a\x0d\x0d\x0a':
                fmt='<' if raw[off+8:off+12]==b'\x4d\x3c\x2b\x1a' else '>';interfaces=[]
            typ,size=struct.unpack_from(fmt+'II',raw,off)
            if size<12 or off+size>len(raw):break
            if typ==1:
                link=struct.unpack_from(fmt+'H',raw,off+8)[0];resolution=1e-6
                opt=off+16;end=off+size-4
                while opt+4<=end:
                    code,length=struct.unpack_from(fmt+'HH',raw,opt);opt+=4
                    if code==0:break
                    val=raw[opt:opt+length];opt+=(length+3)&~3
                    if code==9 and val:
                        r=val[0];resolution=(2**-(r&127)) if r&128 else (10**-r)
                interfaces.append((link,resolution))
            elif typ==6:
                iface,hi,lo,cap,_=struct.unpack_from(fmt+'IIIII',raw,off+8);n+=1
                if iface<len(interfaces):
                    link,res=interfaces[iface];yield n,((hi<<32)|lo)*res,link,raw[off+28:off+28+cap]
            off+=size
    else:raise ValueError('Unsupported capture format: expected PCAP or PCAPNG')

def udp(frame,link):
    if link!=1 or len(frame)<34:return None
    pos=12;eth=struct.unpack_from('!H',frame,pos)[0];ip=14
    for _ in range(2):
        if eth not in (0x8100,0x88a8):break
        if len(frame)<ip+4:return None
        eth=struct.unpack_from('!H',frame,ip+2)[0];ip+=4
    if eth!=0x0800 or len(frame)<ip+20:return None
    ihl=(frame[ip]&15)*4
    if frame[ip]>>4!=4 or ihl<20 or len(frame)<ip+ihl+8 or frame[ip+9]!=17:return None
    frag=struct.unpack_from('!H',frame,ip+6)[0]
    if frag&0x1fff:return None
    total=struct.unpack_from('!H',frame,ip+2)[0]
    u=ip+ihl;sp,dp,length=struct.unpack_from('!HHH',frame,u)
    if length<8 or total<ihl+8:return None
    data=frame[u+8:min(u+length,ip+total,len(frame))]
    return socket.inet_ntoa(frame[ip+12:ip+16]),socket.inet_ntoa(frame[ip+16:ip+20]),sp,dp,data

def parse_tags(data):
    """Best-effort BACnet context tags for object id [0], property id [1], priority [4]."""
    result={};i=0
    while i<len(data):
        first=data[i];i+=1;number=first>>4;context=bool(first&8);l=first&7
        if number==15:
            if i>=len(data):break
            number=data[i];i+=1
        if l in (6,7):continue # opening/closing tags (no payload)
        if l==5:
            if i>=len(data):break
            ext=data[i];i+=1
            if ext==254:
                if i+2>len(data):break
                l=int.from_bytes(data[i:i+2],'big');i+=2
            elif ext==255:
                if i+4>len(data):break
                l=int.from_bytes(data[i:i+4],'big');i+=4
            else:l=ext
        if i+l>len(data):break
        val=data[i:i+l];i+=l
        if context and number==0 and l==4 and 'object' not in result:
            num=int.from_bytes(val,'big');result['object']={'type_id':num>>22,'type':OBJECTS.get(num>>22,'unknown'),'instance':num&0x3fffff}
        elif context and number==1 and 'property_id' not in result and 1<=l<=4:
            v=int.from_bytes(val,'big');result['property_id']=v;result['property']=PROPERTIES.get(v,'unknown')
        elif context and number==4 and l<=4 and 'priority' not in result:
            result['priority']=int.from_bytes(val,'big')
    return result

def bacnet(data):
    if len(data)<6 or data[0]!=0x81:return None
    bvlc_len=int.from_bytes(data[2:4],'big');func=data[1]
    if bvlc_len>len(data) or bvlc_len<6:return None
    pos=4
    if func==4:pos+=6 # forwarded NPDU includes original address
    if pos+2>len(data) or data[pos]!=1:return None
    control=data[pos+1];pos+=2
    if control&0x20:
        if pos+3>len(data):return None
        pos+=2;size=data[pos];pos+=1+size
    if control&0x08:
        if pos+3>len(data):return None
        pos+=2;size=data[pos];pos+=1+size
    if control&0x20:
        pos+=1
    if control&0x80:return {'bvlc_function':func,'kind':'network-layer-message'}
    if pos>=len(data):return {'bvlc_function':func,'kind':'no-apdu'}
    typ=data[pos]>>4;result={'bvlc_function':func,'apdu_type':typ}
    if typ==0: # confirmed request
        if pos+4>len(data):return result
        segmented=bool(data[pos]&8);choice_pos=pos+(5 if segmented else 3)
        if choice_pos>=len(data):return result
        service=data[choice_pos];result.update(kind='confirmed-request',service_id=service,service=SERVICES.get(service,'unknown'),invoke_id=data[pos+2]);
        if service in (12,15):result.update(parse_tags(data[choice_pos+1:]))
    elif typ==1:
        if pos+2<=len(data):
            service=data[pos+1];result.update(kind='unconfirmed-request',service_id=service,service=UNCONFIRMED.get(service,'unknown'))
    elif typ in (2,3,5,6,7):
        result['kind']={2:'simple-ack',3:'complex-ack',5:'error',6:'reject',7:'abort'}[typ]
        if pos+2<len(data) and typ in (2,3,5):
            result['invoke_id']=data[pos+1];svc=data[pos+2] if typ!=3 or not(data[pos]&8) else (data[pos+4] if pos+4<len(data) else None)
            if svc is not None:result['service_id']=svc;result['service']=SERVICES.get(svc,'unknown')
    else:result['kind']='other-apdu'
    return result

def analyze(path,max_events=200):
    counts=collections.Counter();hosts=collections.Counter();services=collections.Counter();events=[];suspicious=[];total=0;bac_count=0
    for no,ts,link,frame in packets(path):
        total+=1;item=udp(frame,link)
        if item is None:continue
        src,dst,sp,dp,payload=item
        if sp!=47808 and dp!=47808:continue
        info=bacnet(payload)
        if info is None:continue
        bac_count+=1;hosts[src]+=1;hosts[dst]+=1
        kind=info.get('kind','unknown');service=info.get('service','unknown');services[f'{kind}: {service}']+=1
        counts[(src,dst)]+=1
        event={'frame':no,'utc':datetime.datetime.fromtimestamp(ts,datetime.timezone.utc).isoformat(),'src':src,'dst':dst,'src_port':sp,'dst_port':dp,**info}
        if kind=='confirmed-request' and info.get('service_id') in (10,11,15,16,17,20):
            event['reason']='Potentially state-changing BACnet service; authorization requires external context';suspicious.append(event)
        if len(events)<max_events:events.append(event)
    return {'capture':str(path),'packets_total':total,'bacnet_packets':bac_count,'hosts':dict(hosts),'services':dict(services),'conversations':[{'src':a,'dst':b,'packets':n} for (a,b),n in counts.most_common()],'state_change_candidates':suspicious,'sample_events':events,'limitations':['Only Ethernet/IPv4/UDP BACnet/IP supported','Best-effort NPDU and object parsing; do not treat unknown fields as authoritative','State-changing requests are not proof of compromise; verify authorization and acknowledgements','No IP fragment reassembly']}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('captures',nargs='+');ap.add_argument('--output',help='Output JSON file (default: stdout)');ap.add_argument('--max-events',type=int,default=30);a=ap.parse_args()
    results=[analyze(p,a.max_events) for p in a.captures];content=json.dumps(results[0] if len(results)==1 else results,indent=2)
    if a.output:pathlib.Path(a.output).write_text(content+'\n',encoding='utf-8');print('Saved',a.output)
    else:print(content)
if __name__=='__main__':main()
