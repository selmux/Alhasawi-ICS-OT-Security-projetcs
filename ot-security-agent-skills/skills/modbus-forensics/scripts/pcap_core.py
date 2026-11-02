"""Read-only, dependency-free PCAP/PCAPNG parser for packet triage.
Supports Ethernet, raw IP, Linux cooked v1, IPv4, and TCP/UDP. PCAPNG: SHB/IDB/EPB/SPB.
Not a replacement for full dissection or TCP reassembly in Wireshark/TShark.
"""
import ipaddress
import struct
from collections import defaultdict
from pathlib import Path

PORTS = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',102:'S7comm (candidate)',135:'MSRPC',139:'NetBIOS',443:'HTTPS/TLS',445:'SMB',502:'Modbus TCP (candidate)',1433:'MSSQL',1880:'Node-RED HTTP',1883:'MQTT',2404:'IEC-104 (candidate)',3000:'HTTP/Grafana (candidate)',3306:'MySQL/MariaDB',3389:'RDP',47808:'BACnet/IP (candidate)',8080:'HTTP (alternate)',8086:'InfluxDB HTTP'}
class CaptureError(Exception): pass

def records(path):
    with open(path,'rb') as f:
        magic=f.read(4); f.seek(0)
        if magic in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'):
            endian='<' if magic[0] in (0xd4,0x4d) else '>'
            nanos=magic in (b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d')
            hdr=f.read(24)
            if len(hdr)!=24: raise CaptureError('Truncated PCAP header')
            link=struct.unpack_from(endian+'I',hdr,20)[0]
            n=0
            while True:
                h=f.read(16)
                if not h: break
                if len(h)!=16: raise CaptureError('Truncated packet header')
                sec,sub,cap,original=struct.unpack(endian+'IIII',h)
                if cap>64_000_000: raise CaptureError('Implausible record length')
                data=f.read(cap)
                if len(data)!=cap: raise CaptureError('Truncated packet data')
                n+=1
                yield n,sec+sub/(1e9 if nanos else 1e6),link,data
        elif magic==b'\x0a\x0d\x0d\x0a':
            e=None; interfaces=[]; n=0
            while True:
                head=f.read(8)
                if not head: break
                if len(head)<8: raise CaptureError('Truncated PCAPNG block')
                if head[:4]==b'\x0a\x0d\x0d\x0a':
                    bom=f.read(4)
                    e='<' if bom==b'\x4d\x3c\x2b\x1a' else '>' if bom==b'\x1a\x2b\x3c\x4d' else None
                    if e is None: raise CaptureError('Invalid byte-order magic')
                    length=struct.unpack(e+'I',head[4:])[0]
                    if length<28 or length>64_000_000: raise CaptureError('Invalid section length')
                    remaining=f.read(length-12)
                    if len(remaining)!=length-12: raise CaptureError('Truncated section')
                    interfaces=[]; continue
                if e is None: raise CaptureError('No PCAPNG section')
                typ,length=struct.unpack(e+'II',head)
                if length<12 or length>64_000_000 or length%4: raise CaptureError('Invalid block size')
                block=f.read(length-8)
                if len(block)!=length-8: raise CaptureError('Truncated block')
                if struct.unpack_from(e+'I',block,len(block)-4)[0]!=length: raise CaptureError('Mismatched block length')
                body=block[:-4]
                if typ==1 and len(body)>=8:
                    link=struct.unpack_from(e+'H',body)[0]
                    resol=1e-6; offset=0
                    pos=8
                    while pos+4<=len(body):
                        code,sz=struct.unpack_from(e+'HH',body,pos);pos+=4
                        val=body[pos:pos+sz];pos+=(sz+3)//4*4
                        if code==9 and val:
                            b=val[0]; resol=(2 if b&128 else 10)**-(b&127)
                        if code==14 and len(val)==8: offset=struct.unpack(e+'q',val)[0]
                        if code==0: break
                    interfaces.append((link,resol,offset))
                elif typ==6 and len(body)>=20:
                    iface,hi,lo,cap,orig=struct.unpack_from(e+'IIIII',body)
                    if iface>=len(interfaces) or 20+cap>len(body): continue
                    link,resol,offset=interfaces[iface]; n+=1
                    yield n,((hi<<32)|lo)*resol+offset,link,body[20:20+cap]
                elif typ==3 and len(body)>=4 and interfaces:
                    link,_,_=interfaces[0];n+=1
                    yield n,None,link,body[4:]
        else: raise CaptureError('Not a PCAP or PCAPNG file')

def parse_packet(n,ts,link,raw):
    p={'frame':n,'time':ts,'linktype':link,'length':len(raw)}
    try:
        if link==1:
            if len(raw)<14:return p
            typ=int.from_bytes(raw[12:14],'big');off=14
            while typ in (0x8100,0x88a8,0x9100) and len(raw)>=off+4:
                typ=int.from_bytes(raw[off+2:off+4],'big');off+=4
        elif link==101: typ=0x0800 if raw and raw[0]>>4==4 else 0x86dd; off=0
        elif link==113:
            if len(raw)<16:return p
            typ=int.from_bytes(raw[14:16],'big');off=16
        else:return p
        if typ==0x0800:
            if len(raw)<off+20 or raw[off]>>4!=4:return p
            ihl=(raw[off]&15)*4;proto=raw[off+9]
            if ihl<20 or len(raw)<off+ihl:return p
            p['src']=str(ipaddress.IPv4Address(raw[off+12:off+16]));p['dst']=str(ipaddress.IPv4Address(raw[off+16:off+20]));off+=ihl
            frag=int.from_bytes(raw[off-ihl+6:off-ihl+8],'big')&0x1fff
            if frag:return p
        elif typ==0x86dd:
            if len(raw)<off+40:return p
            proto=raw[off+6];p['src']=str(ipaddress.IPv6Address(raw[off+8:off+24]));p['dst']=str(ipaddress.IPv6Address(raw[off+24:off+40]));off+=40
            # Extension headers: fail closed rather than misparse
            if proto in (0,43,44,50,51,60):return p
        else:return p
        if proto==6 and len(raw)>=off+20:
            sport,dport=struct.unpack_from('!HH',raw,off);hsize=(raw[off+12]>>4)*4
            if hsize<20 or len(raw)<off+hsize:return p
            p.update(protocol='TCP',sport=sport,dport=dport,seq=struct.unpack_from('!I',raw,off+4)[0],flags=raw[off+13],payload=raw[off+hsize:])
        elif proto==17 and len(raw)>=off+8:
            sport,dport=struct.unpack_from('!HH',raw,off)
            length=struct.unpack_from('!H',raw,off+4)[0]
            p.update(protocol='UDP',sport=sport,dport=dport,payload=raw[off+8:off+max(8,length)] if length>=8 else b'')
        else:p['protocol']=str(proto)
    except (ValueError,struct.error):pass
    return p

def load(path,max_packets=300000):
    result=[]
    for i,rec in enumerate(records(path)):
        if i>=max_packets: raise CaptureError('Packet limit exceeded; set --max-packets higher for trusted inputs')
        result.append(parse_packet(*rec))
    return result

def service(p):
    ports=(p.get('sport'),p.get('dport'))
    for x in (p.get('dport'),p.get('sport')):
        if x in PORTS: return PORTS[x]
    return 'Unknown'

def convkey(p):
    a=(p['src'],p['sport']);b=(p['dst'],p['dport'])
    return (p['protocol'],*sorted((a,b)))

def conversations(packets):
    c={}
    for p in packets:
        if 'sport' not in p: continue
        k=convkey(p)
        if k not in c:c[k]={'protocol':k[0],'endpoint_a':{'ip':k[1][0],'port':k[1][1]},'endpoint_b':{'ip':k[2][0],'port':k[2][1]},'packets':0,'payload_bytes':0,'first_frame':p['frame'],'last_frame':p['frame'],'first_time':p['time'],'last_time':p['time'],'services':set()}
        v=c[k];v['packets']+=1;v['payload_bytes']+=len(p.get('payload',b''));v['last_frame']=p['frame'];v['last_time']=p['time'];v['services'].add(service(p))
    for v in c.values():v['services']=sorted(v['services'])
    return sorted(c.values(),key=lambda v:v['packets'],reverse=True)

def summarize(packets):
    from collections import Counter
    return {'packet_count':len(packets),'first_time':next((p['time'] for p in packets if p['time'] is not None),None),'last_time':next((p['time'] for p in reversed(packets) if p['time'] is not None),None),'linktypes':dict(Counter(p['linktype'] for p in packets)),'protocols':dict(Counter(p.get('protocol','Other') for p in packets)),'services':dict(Counter(service(p) for p in packets if 'sport' in p)),'hosts':dict(Counter(ip for p in packets for ip in (p.get('src'),p.get('dst')) if ip)),'conversations':conversations(packets)[:50]}
