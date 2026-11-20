#!/usr/bin/env python3
"""Offline educational evidence integration. Python 3.10+, stdlib core.
Does not execute samples, acquire RAM, or modify source evidence.
"""
import argparse
import csv
import hashlib
import html
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

FIELDS = ['timestamp','source','host','event_type','description','src_ip','dst_ip','src_port','dst_port','pid','path','sha256','evidence_ref']
SOURCES = {'host','attacker','network'}

def stamp(value):
    s = str(value).strip()
    if not s:
        return None
    try:
        n = float(s)
        if not math.isfinite(n):
            raise ValueError('non-finite time')
        return n
    except ValueError:
        d = datetime.fromisoformat(s.replace(' UTC','+00:00').replace('Z','+00:00'))
        if d.tzinfo is None:
            raise ValueError('timestamp needs timezone, e.g. 2026-10-10T10:00:00+05:30')
        return d.timestamp()

def iso(n):
    return datetime.fromtimestamp(n, timezone.utc).isoformat().replace('+00:00','Z') if n is not None else ''

def digest(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()

def connect(case):
    p = Path(case)
    if not (p/'case.json').exists():
        raise ValueError('Case missing. Run init first.')
    db = sqlite3.connect(p/'case.db')
    db.row_factory = sqlite3.Row
    db.executescript('''
    CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, path TEXT, sha256 TEXT, size INTEGER, registered_utc TEXT, collector TEXT, note TEXT, UNIQUE(path,sha256));
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, source TEXT, host TEXT, event_type TEXT, description TEXT, src_ip TEXT, dst_ip TEXT, src_port TEXT, dst_port TEXT, pid TEXT, path TEXT, sha256 TEXT, evidence_ref TEXT, input_sha256 TEXT, input_row TEXT, UNIQUE(input_sha256,input_row));
    CREATE TABLE IF NOT EXISTS packets(id INTEGER PRIMARY KEY, time REAL, src TEXT, dst TEXT, proto TEXT, sport INTEGER, dport INTEGER, length INTEGER, is_syn INTEGER, evidence_sha256 TEXT, input_row TEXT, UNIQUE(evidence_sha256,input_row));
    ''')
    return db

def evidence_path(db,p):
    base=Path(db.execute('PRAGMA database_list').fetchone()[2]).parent
    try: return os.path.relpath(p,base)
    except ValueError: return str(p)  # different Windows drive

def resolve_evidence(db,p):
    path=Path(p)
    if path.is_absolute():return path
    return Path(db.execute('PRAGMA database_list').fetchone()[2]).parent/path

def register(db, p, collector, note):
    p = Path(p).resolve()
    if not p.is_file(): raise ValueError(f'File missing: {p}')
    before=p.stat()
    h=digest(p)
    after=p.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
        raise ValueError('Evidence changed while hashing; stop collection and retry.')
    db.execute('INSERT OR IGNORE INTO evidence(path,sha256,size,registered_utc,collector,note) VALUES(?,?,?,?,?,?)',
               (evidence_path(db,p),h,after.st_size,iso(datetime.now(timezone.utc).timestamp()),collector,note))
    return h

def add_event(db, r, h, row):
    source=r.get('source','')
    if source not in SOURCES: raise ValueError('source must be host, attacker or network')
    if not r.get('description') or not r.get('evidence_ref'): raise ValueError('description and evidence_ref are required')
    ts=stamp(r.get('timestamp',''))
    vals=[ts]+[str(r.get(k,'') or '') for k in FIELDS[1:]]+[h,str(row)]
    db.execute('INSERT OR IGNORE INTO events(ts,source,host,event_type,description,src_ip,dst_ip,src_port,dst_port,pid,path,sha256,evidence_ref,input_sha256,input_row) VALUES('+','.join('?' for _ in vals)+')',vals)

def load_csv(db, path, collector):
    h=register(db,path,collector,'Normalized findings CSV; original artifact must also be registered')
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f)
        if not set(FIELDS)<=set(reader.fieldnames or []): raise ValueError('CSV header must match templates/events.csv')
        for line,r in enumerate(reader,2):
            try: add_event(db,r,h,line)
            except (ValueError,OverflowError) as e: raise ValueError(f'{path}: row {line}: {e}') from e

def add_packet(db,r,h,row):
    t=stamp(r['time'])
    if t is None: raise ValueError('Packet time missing')
    syn=r['is_syn']
    if str(syn).lower() not in ('0','1','false','true'): raise ValueError('Invalid is_syn value')
    vals=(t,str(r['src']),str(r['dst']),str(r['proto']),int(r['sport']),int(r['dport']),int(r['length']),int(str(syn).lower() in ('1','true')),h,str(row))
    db.execute('INSERT OR IGNORE INTO packets(time,src,dst,proto,sport,dport,length,is_syn,evidence_sha256,input_row) VALUES(?,?,?,?,?,?,?,?,?,?)',vals)

def load_network(db,path,collector):
    path=Path(path)
    h=register(db,path,collector,'Network source; PCAP frame or database row tracked')
    if path.suffix.lower() in ('.db','.sqlite','.sqlite3'):
        src=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
        src.row_factory=sqlite3.Row
        try:
            for i,r in enumerate(src.execute('SELECT time,src,dst,proto,sport,dport,length,is_syn FROM packets'),1): add_packet(db,r,h,i)
        finally: src.close()
    else:
        from packet_reader import packets
        for i,r in packets(path): add_packet(db,r,h,i)
    if digest(path)!=h: raise ValueError('Network input changed during import')

def load_vol(db,path,kind,host,collector):
    h=register(db,path,collector,'Volatility CSV export; register memory image separately')
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f)
        required={'PID','ImageFileName','CreateTime'} if kind=='pslist' else {'PID','LocalAddr','LocalPort','ForeignAddr','ForeignPort','Created'}
        if not required<=set(reader.fieldnames or []): raise ValueError(f'Expected Volatility {kind} CSV columns: {sorted(required)}')
        for i,r in enumerate(reader,2):
            when=r.get('CreateTime' if kind=='pslist' else 'Created','')
            if when in ('N/A','N/A (NotApplicable)','Unreadable','-','NotApplicable'): when=''
            e=dict(timestamp=when,source='host',host=host,event_type='memory_'+kind,pid=r.get('PID',''),evidence_ref=f'{Path(path).name}:CSV row {i}',description=json.dumps(r,ensure_ascii=False))
            if kind=='netscan':
                e.update(src_ip=r['LocalAddr'],dst_ip=r['ForeignAddr'],src_port=r['LocalPort'],dst_port=r['ForeignPort'])
            add_event(db,e,h,i)

def export_csv(path, fields, rows):
    with Path(path).open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

def report(db,case,window):
    cfg=json.loads((Path(case)/'case.json').read_text())
    out=Path(case)/'reports'; out.mkdir(exist_ok=True)
    events=[]
    for r in db.execute('SELECT * FROM events ORDER BY ts,id'):
        d=dict(r);d['timestamp']=iso(d.pop('ts')); events.append(d)
    # Keep capture sources separate. The thresholds mirror teammate's code,
    # but interpretations explicitly remain hypotheses.
    alerts=[]
    for r in db.execute('''SELECT evidence_sha256,src,dst,MIN(time) start,MAX(time) end,COUNT(DISTINCT dport) ports,COUNT(*) n FROM packets WHERE is_syn=1 GROUP BY evidence_sha256,src,dst'''):
        if r['ports']>15: alerts.append(dict(r)|{'type':'Possible port scan','detail':f"{r['ports']} distinct SYN destination ports across this capture"})
    for r in db.execute('''SELECT evidence_sha256,src,dst,MIN(time) start,MAX(time) end,COUNT(*) n FROM packets WHERE is_syn=1 AND dport=22 GROUP BY evidence_sha256,src,dst'''):
        if r['n']>20: alerts.append(dict(r)|{'type':'Repeated SSH connections','detail':f"{r['n']} SYN packets to port 22; not a password-attempt count"})
    for r in db.execute('''SELECT evidence_sha256,src,dst,dport,MIN(time) start,MAX(time) end,SUM(length) bytes FROM packets GROUP BY evidence_sha256,src,dst,dport HAVING SUM(length)>40000'''):
        alerts.append(dict(r)|{'type':'Large captured flow','detail':f"{r['bytes']} captured frame bytes to destination port {r['dport']}; not proof of file theft"})
    network=[]
    for i,a in enumerate(alerts,1):
        network.append(dict(timestamp=iso(a['start']),source='network',host=a['src'],event_type=a['type'],description=a['detail']+'; ends '+iso(a['end']),src_ip=a['src'],dst_ip=a['dst'],src_port='',dst_port=str(a.get('dport','')),pid='',path='',sha256='',evidence_ref='capture SHA256 '+a['evidence_sha256'],id='N'+str(i),input_sha256=a['evidence_sha256'],input_row='aggregate'))
    timeline=events+network
    timeline.sort(key=lambda x:(x['timestamp']=='',x['timestamp'],str(x['id'])))
    export_csv(out/'timeline.csv',FIELDS+['id','input_sha256','input_row'],timeline)
    # Exact endpoint pair + bounded time only; PID never inferred from packets.
    links=[]
    for e in events:
        if e['source'] not in ('host','attacker') or not e['timestamp'] or not e['src_ip'] or not e['dst_ip']: continue
        t=stamp(e['timestamp'])
        for direction in ('forward','reverse'):
            si,di=(e['src_ip'],e['dst_ip']) if direction=='forward' else (e['dst_ip'],e['src_ip'])
            sp,dp=(e['src_port'],e['dst_port']) if direction=='forward' else (e['dst_port'],e['src_port'])
            sql='SELECT evidence_sha256,MIN(time) first,MAX(time) last,COUNT(*) n,MIN(CAST(input_row AS INTEGER)) example_row FROM packets WHERE src=? AND dst=? AND time BETWEEN ? AND ?'
            params=[si,di,t-window,t+window]
            for col,val in [('sport',sp),('dport',dp)]:
                if val and val not in ('*','-'): sql+=' AND '+col+'=?'; params.append(int(val))
            sql+=' GROUP BY evidence_sha256'
            for r in db.execute(sql,params):
                links.append(dict(event_id=e['id'],direction=direction,packet_count=r['n'],first_utc=iso(r['first']),last_utc=iso(r['last']),capture_sha256=r['evidence_sha256'],example_input_row=r['example_row'],basis=f'Endpoint/time candidate within +/-{window}s; validate clock offset and artifact meaning.'))
    lf=['event_id','direction','packet_count','first_utc','last_utc','capture_sha256','example_input_row','basis']
    export_csv(out/'correlations.csv',lf,links)
    ev=[dict(r) for r in db.execute('SELECT * FROM evidence')]
    export_csv(out/'evidence_manifest.csv',['id','path','sha256','size','registered_utc','collector','note'],ev)
    root=ET.Element('case',name=cfg['name'],mode=cfg['mode'])
    for e in timeline:
        n=ET.SubElement(root,'event')
        for k,v in e.items(): ET.SubElement(n,k).text=str(v)
    ET.ElementTree(root).write(out/'timeline.xml',encoding='utf-8',xml_declaration=True)
    count=db.execute('SELECT COUNT(*) FROM packets').fetchone()[0]
    host_count=sum(e['source']=='host' for e in events)
    attacker_count=sum(e['source']=='attacker' for e in events)
    status=dict(case=cfg['name'],mode=cfg['mode'],packets=count,host_findings=host_count,attacker_notes=attacker_count,network_hypotheses=len(alerts),candidate_links=len(links),missing=[])
    if not host_count: status['missing'].append('Host findings: memory, disk and sample analysis not yet supplied')
    if not attacker_count: status['missing'].append('Attacker notes not yet supplied')
    limitations_file=Path(case)/'project_limitations.json'
    if limitations_file.is_file():
        status['missing'].extend(json.loads(limitations_file.read_text(encoding='utf-8')))
    (out/'summary.json').write_text(json.dumps(status,indent=2),encoding='utf-8')
    def table(rows,cols):
        return '<table><thead><tr>'+''.join('<th>'+html.escape(k)+'</th>' for k in cols)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+html.escape(str(r.get(k,'')))+'</td>' for k in cols)+'</tr>' for r in rows)+'</tbody></table>'
    body=f'''<!doctype html><html><head><meta charset="utf-8"><title>Forensic case report</title><style>body{{font:15px system-ui;margin:35px;background:#f4f6fa;color:#17253d}}h1{{color:#123b65}}table{{border-collapse:collapse;background:white;width:100%;font-size:12px}}td,th{{border:1px solid #d2dbe5;padding:9px;text-align:left;overflow-wrap:anywhere;max-width:350px}}th{{background:#dfeafa}}.notice{{padding:16px;background:#fff0c9;border-left:5px solid #c98d00}}input{{padding:12px;width:70%;margin:20px 0}}section{{overflow:auto;margin:25px 0}}@media print{{input{{display:none}}body{{margin:8px}}}}</style></head><body><h1>{html.escape(cfg['name'])}</h1><p>Mode: <b>{html.escape(cfg['mode'])}</b> | Sidharth U · Machine forensics</p><div class="notice">Evidence observations and candidate links are not proof of compromise. SYN counts do not count failed logins; captured bytes do not identify a stolen file. Untimed artifacts remain untimed. Missing evidence is not a negative finding.</div><pre>{html.escape(json.dumps(status,indent=2))}</pre><input id="q" placeholder="Search timeline by IP, PID, file, event or evidence"><section id="timeline"><h2>Combined timeline (UTC)</h2>{table(timeline,['timestamp','source','host','event_type','description','evidence_ref','id'])}</section><section><h2>Candidate network links</h2>{table(links,lf)}</section><section><h2>Evidence register</h2>{table(ev,['id','path','sha256','size','collector','note'])}</section><p>Original evidence and tool exports must be retained. Registry creation records receipt; it is not a complete chain of custody. See custody.csv.</p><script>document.getElementById('q').addEventListener('input',function(){{let q=this.value.toLowerCase();document.querySelectorAll('#timeline tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q));}});</script></body></html>'''
    (out/'report.html').write_text(body,encoding='utf-8')
    print(json.dumps(status,indent=2));print('Open',out/'report.html')

def run_vol(args):
    case=Path(args.case)
    if not (case/'case.json').exists(): raise ValueError('Run init first')
    mem=Path(args.memory).resolve(); vol=Path(args.vol).resolve()
    if not mem.is_file() or not vol.is_file(): raise ValueError('Memory image or vol.py missing')
    out=case/'volatility'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');out.mkdir(parents=True)
    results=[]
    plugins = ['banners.Banners','linux.pslist.PsList','linux.pstree.PsTree','linux.bash.Bash'] if args.os == 'linux' else ['windows.info','windows.pslist','windows.pstree','windows.cmdline','windows.netscan']
    for plugin in plugins:
        cmd=[sys.executable,str(vol),'--offline','-q','-r','csv','-f',str(mem),plugin]
        with (out/(plugin+'.csv')).open('wb') as stdout,(out/(plugin+'.stderr.txt')).open('wb') as stderr:
            try:
                p=subprocess.run(cmd,stdout=stdout,stderr=stderr,timeout=args.timeout,check=False)
                code=p.returncode
            except subprocess.TimeoutExpired: code=124
        results.append(dict(plugin=plugin,returncode=code,command=cmd))
        print(plugin, 'OK - inspect export' if code==0 else 'FAILED - see stderr')
    (out/'run_status.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    print('Exports:',out)
    return 1 if any(x['returncode'] for x in results) else 0

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('init');a.add_argument('--case',required=True);a.add_argument('--name',default='Cyber Range Investigation');a.add_argument('--mode',choices=['REAL','SYNTHETIC DEMO'],default='REAL')
    for name in ['register','import-events','import-network','import-vol','report','verify']:
        a=sub.add_parser(name);a.add_argument('--case',required=True)
        if name not in ('report','verify'): a.add_argument('--file',required=True);a.add_argument('--collector',default='Sidharth U')
        if name=='register': a.add_argument('--note',required=True)
        if name=='import-vol': a.add_argument('--kind',choices=['pslist','netscan'],required=True);a.add_argument('--host',required=True)
        if name=='report': a.add_argument('--window',type=int,default=60)
    a=sub.add_parser('run-vol');a.add_argument('--case',required=True);a.add_argument('--memory',required=True);a.add_argument('--vol',required=True);a.add_argument('--timeout',type=int,default=600);a.add_argument('--os',choices=['linux','windows'],default='linux')
    args=p.parse_args(argv)
    try:
        if args.cmd=='init':
            case=Path(args.case)
            if (case/'case.json').exists(): raise ValueError('Case already exists; choose a new folder')
            case.mkdir(parents=True,exist_ok=True)
            (case/'case.json').write_text(json.dumps(dict(name=args.name,mode=args.mode),indent=2),encoding='utf-8')
            with connect(case): pass
            export_csv(case/'custody.csv',['timestamp_utc','evidence_sha256','from_person','to_person','action','purpose','storage_location','notes'],[])
            print('Created',case);return 0
        if args.cmd=='run-vol': return run_vol(args)
        with connect(args.case) as db:
            if args.cmd=='register': print(register(db,args.file,args.collector,args.note))
            elif args.cmd=='import-events': load_csv(db,args.file,args.collector)
            elif args.cmd=='import-network': load_network(db,args.file,args.collector)
            elif args.cmd=='import-vol': load_vol(db,args.file,args.kind,args.host,args.collector)
            elif args.cmd=='report':
                if not 0<=args.window<=86400: raise ValueError('window must be 0..86400 seconds')
                report(db,args.case,args.window)
            elif args.cmd=='verify':
                failed=False
                for r in db.execute('SELECT * FROM evidence'):
                    ep=resolve_evidence(db,r['path']);ok=ep.is_file() and digest(ep)==r['sha256']
                    print('OK' if ok else 'MISSING/CHANGED',r['path']);failed|=not ok
                return int(failed)
        return 0
    except (OSError,ValueError,sqlite3.Error,KeyError,OverflowError,csv.Error) as e:
        print('ERROR:',e,file=sys.stderr);return 2

if __name__=='__main__': sys.exit(main())
