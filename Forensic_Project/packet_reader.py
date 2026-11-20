"""Offline dpkt adapter; no live interface or raw-socket access."""
import socket
import struct
from pathlib import Path

def validate_pcapng(path):
    # dpkt uses the first interface/timebase. Reject captures it could mislabel.
    sections=interfaces=0
    endian=None
    with Path(path).open('rb') as f:
        while True:
            head=f.read(8)
            if not head:break
            if len(head)!=8:raise ValueError('Truncated PCAPNG block header')
            if head[:4]==b'\x0a\x0d\x0d\x0a':
                bom=f.read(4)
                if bom==b'\x4d\x3c\x2b\x1a':endian='<'
                elif bom==b'\x1a\x2b\x3c\x4d':endian='>'
                else:raise ValueError('Invalid PCAPNG byte order')
                sections+=1;consumed=12
                if sections>1:raise ValueError('Multi-section PCAPNG unsupported; export one interface/section or use traffic.db')
            else:consumed=8
            if endian is None:raise ValueError('Missing PCAPNG section')
            typ,size=struct.unpack(endian+'II',head)
            if size<consumed+4 or size%4:raise ValueError('Invalid PCAPNG block size')
            body=f.read(size-consumed)
            if len(body)!=size-consumed or struct.unpack(endian+'I',body[-4:])[0]!=size:raise ValueError('Truncated or invalid PCAPNG block')
            if typ==1:
                interfaces+=1
                if interfaces>1:raise ValueError('Multi-interface PCAPNG unsupported; export one interface or use traffic.db')
            if typ==6 and (len(body)<8 or struct.unpack(endian+'I',body[:4])[0]!=0):raise ValueError('Unknown PCAPNG packet interface')
            if typ in (2,3):raise ValueError('Legacy/simple PCAPNG packet block unsupported; use traffic.db or convert capture')

def packets(path):
    try: import dpkt
    except ImportError as e: raise ValueError('PCAP import needs dpkt: python -m pip install -r requirements.txt') from e
    with Path(path).open('rb') as f:
        magic=f.read(4);f.seek(0)
        if magic==b'\x0a\x0d\x0d\x0a':validate_pcapng(path)
        try:
            reader=dpkt.pcapng.Reader(f) if magic==b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(f)
            link=reader.datalink()
            if link not in (1,101,12,113): raise ValueError(f'Unsupported capture link type {link}; export Ethernet PCAP from Wireshark or use traffic.db')
            for i,(ts,buf) in enumerate(reader,1):
                if link==1: ip=dpkt.ethernet.Ethernet(buf).data
                elif link==113: ip=dpkt.sll.SLL(buf).data
                else: ip=dpkt.ip6.IP6(buf) if buf and buf[0]>>4==6 else dpkt.ip.IP(buf)
                if not isinstance(ip,(dpkt.ip.IP,dpkt.ip6.IP6)): continue
                family=socket.AF_INET if isinstance(ip,dpkt.ip.IP) else socket.AF_INET6
                r=dict(time=float(ts),src=socket.inet_ntop(family,ip.src),dst=socket.inet_ntop(family,ip.dst),proto='OTHER',sport=0,dport=0,length=len(buf),is_syn=0)
                transport=ip.data
                if isinstance(transport,dpkt.tcp.TCP):
                    flags=transport.flags
                    r.update(proto='TCP',sport=transport.sport,dport=transport.dport,is_syn=int(bool(flags&2) and not bool(flags&16)))
                elif isinstance(transport,dpkt.udp.UDP): r.update(proto='UDP',sport=transport.sport,dport=transport.dport)
                yield i,r
        except (dpkt.UnpackError,ValueError,IndexError) as e:
            raise ValueError(f'Capture parse failed: {e}. For multi-interface PCAPNG, export a single-interface PCAP or use teammate traffic.db.') from e
