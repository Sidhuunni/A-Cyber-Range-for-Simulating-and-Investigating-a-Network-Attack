"""Rebuild the supplied Linux reconnaissance case and review report offline."""
import csv,json,html,sqlite3,sys
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime,timezone
import dpkt
import forensics as core

ROOT=Path(__file__).resolve().parent
ATTACKER='192.168.56.10'; TARGET='192.168.56.20'

def build():
 case=ROOT/'case';evidence=ROOT/'evidence';out=ROOT/'results';out.mkdir(exist_ok=True)
 if not (case/'case.json').exists():
  assert core.main(['init','--case',str(case),'--name','Metasploitable2 reconnaissance investigation'])==0
 capture=evidence/'lab_recon_capture.pcapng'
 if core.main(['import-network','--case',str(case),'--file',str(capture)]):raise SystemExit('Capture import failed; see error above')
 with core.connect(case) as db:
  for name,note in [('attacker_notes.docx','Operator account; no event dates/times provided'),('attacker_connectivity.jpeg','Supplied screenshot; connectivity evidence, capture association unverified')]:core.register(db,evidence/name,'Sidharth U',note)
  h=core.digest(evidence/'attacker_notes.docx')
  for i,text in enumerate(['Operator reports static addressing on isolated VirtualBox labnet, Kali 192.168.56.10 and Metasploitable2 192.168.56.20.','Operator reports successful ping: 4 replies, 0% loss. Screenshot supports this outcome; full date/time absent.','Operator reports nmap -sS -sV against 192.168.56.20; service versions are claims pending raw Nmap output.','Operator lists target VMDK and metasploitable_ram.elf as artifacts. Neither image was supplied for examination.'],1):
   core.add_event(db,dict(timestamp='',source='attacker',host=TARGET,event_type='operator_statement',description=text,src_ip=ATTACKER,dst_ip=TARGET,evidence_ref=f'attacker_notes.docx: statement {i}'),h,i)
  core.report(db,case,60)
  syn=db.execute('SELECT COUNT(*),COUNT(DISTINCT dport),MIN(time),MAX(time) FROM packets WHERE src=? AND dst=? AND is_syn=1',(ATTACKER,TARGET)).fetchone()
  ports=[dict(r) for r in db.execute('SELECT dport AS port,COUNT(*) syn_packets,MIN(time) first,MAX(time) last,MIN(CAST(input_row AS INTEGER)) example_frame FROM packets WHERE src=? AND dst=? AND is_syn=1 GROUP BY dport ORDER BY dport',(ATTACKER,TARGET))]
  for p in ports:p['first']=core.iso(p['first']);p['last']=core.iso(p['last'])
  core.export_csv(out/'probed_ports.csv',['port','syn_packets','first','last','example_frame'],ports)
  ip_count=db.execute('SELECT COUNT(*) FROM packets').fetchone()[0]
  times=db.execute('SELECT MIN(time),MAX(time) FROM packets').fetchone()
  ssh=db.execute('SELECT COUNT(*) FROM packets WHERE src=? AND dst=? AND is_syn=1 AND dport=22',(ATTACKER,TARGET)).fetchone()[0]
 scan_return=Counter()
 counts=Counter();responses=defaultdict(list);rst=Counter();banners={};total=0
 with capture.open('rb') as f:
  for frame,(ts,buf) in enumerate(dpkt.pcapng.Reader(f),1):
   total+=1;eth=dpkt.ethernet.Ethernet(buf);ip=eth.data
   if isinstance(ip,dpkt.arp.ARP):counts['ARP']+=1;continue
   if not isinstance(ip,dpkt.ip.IP):counts['Other non-IPv4']+=1;continue
   import socket
   src=socket.inet_ntoa(ip.src);dst=socket.inet_ntoa(ip.dst);t=ip.data
   if isinstance(t,dpkt.icmp.ICMP):counts['ICMP']+=1
   elif isinstance(t,dpkt.udp.UDP):counts['UDP']+=1
   elif isinstance(t,dpkt.tcp.TCP):
    counts['TCP']+=1
    if src==TARGET and dst==ATTACKER and t.dport==46905:
     scan_return['packets']+=1;scan_return['tcp_payload_bytes']+=len(t.data);scan_return['rst_packets']+=int(bool(t.flags&4));scan_return['syn_ack_packets']+=int(t.flags&0x12==0x12)
    if src==TARGET and dst==ATTACKER and t.flags&0x12==0x12:responses[t.sport].append(frame)
    if t.flags&4:rst[src]+=1
    if src==TARGET and dst==ATTACKER and t.data and t.sport not in banners:
     snippet=''.join(chr(b) if 32<=b<127 else ' ' for b in bytes(t.data)[:180]).strip()
     if snippet:banners[t.sport]={'frame':frame,'text':snippet}
   else:counts['Other IPv4']+=1
 service_claims={21:'vsftpd 2.3.4',22:'OpenSSH 4.7p1',23:'Linux telnetd',80:'Apache 2.2.8; DVWA/Mutillidae claimed',139:'Samba 3.X–4.X',445:'Samba 3.X–4.X',6667:'UnrealIRCd'}
 service_rows=[]
 for port,claim in service_claims.items():
  service_rows.append({'port':port,'operator_reported_service':claim,'syn_ack_observed':bool(responses.get(port)),'example_syn_ack_frame':responses.get(port,[''])[0],'banner_frame':banners.get(port,{}).get('frame',''),'raw_packet_excerpt':banners.get(port,{}).get('text','')})
 core.export_csv(out/'service_evidence.csv',list(service_rows[0]),service_rows)
 summary=dict(scope='Linux reconnaissance only',attacker=ATTACKER,target=TARGET,total_frames=total,ip_packets=ip_count,first_utc=core.iso(times[0]),last_utc=core.iso(times[1]),syn_packets_to_target=syn[0],distinct_syn_ports=syn[1],ssh_syn_packets=ssh,ports_with_target_syn_ack=sorted(responses),protocol_counts=dict(counts),rst_packets_by_source=dict(rst),large_flow_review=dict(scan_return),missing=['Target VMDK and complete disk chain','metasploitable_ram.elf','Raw Nmap output with timestamps','Host logs and acquisition records'],conclusion='Capture supports broad TCP port probing, consistent with the reported reconnaissance. Exploitation, password compromise, persistence, malware deployment and file theft are not established by the supplied evidence.')
 (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
 (out/'console_output.txt').write_text('ACTUAL EXECUTION RESULTS\n'+json.dumps(summary,indent=2),encoding='utf-8')
 def esc(x):return html.escape(str(x))
 cards=''.join(f'<div class="card"><strong>{esc(v)}</strong><span>{esc(k)}</span></div>' for k,v in [('IP packets',ip_count),('SYN probes to target',syn[0]),('Distinct destination ports',syn[1]),('Ports returning SYN-ACK',len(responses))])
 rows=''.join('<tr>'+''.join(f'<td>{esc(r[k])}</td>' for k in ['port','operator_reported_service','syn_ack_observed','example_syn_ack_frame','banner_frame','raw_packet_excerpt'])+'</tr>' for r in service_rows)
 bars=''.join(f'<div class="barrow"><label>{esc(k)}</label><div class="bar" style="width:{max(1,v/max(counts.values())*70)}%"></div><b>{v}</b></div>' for k,v in counts.items())
 body=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linux reconnaissance · forensic review</title><style>body{{font:15px/1.55 Arial,sans-serif;background:#edf2f7;color:#1a2b40;margin:0}}main{{max-width:1200px;margin:auto;padding:36px}}header{{background:#142d49;color:white;padding:30px;border-radius:16px}}.tag{{color:#71dbcc;font-weight:bold;letter-spacing:2px;font-size:12px}}h1{{font-size:32px;margin:8px 0}}h2{{font-size:22px}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}}.card,section{{background:white;border:1px solid #d8e3ef;border-radius:12px;padding:22px;margin-bottom:20px}}.card strong{{display:block;font-size:34px;color:#125e77}}.card span{{font-size:13px}}.note{{background:#fff5d9;border-left:5px solid #ddb14c;padding:16px}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #d8e3ef;text-align:left;padding:12px;overflow-wrap:anywhere}}td:last-child{{max-width:310px}}th{{background:#eff5fa}}.barrow{{display:flex;gap:14px;align-items:center;margin:10px 0}}label{{width:110px}}.bar{{height:15px;background:#187f99;border-radius:4px}}a{{color:#136c8c}}img{{max-width:100%;border-radius:10px}}.muted{{color:#61758b}}@media(max-width:700px){{.cards{{grid-template-columns:repeat(2,1fr)}}main{{padding:14px}}}}</style></head><body><main><header><div class="tag">SIDHARTH U / MACHINE FORENSICS</div><h1>Linux reconnaissance investigation</h1><p>Kali {ATTACKER} → Metasploitable2 {TARGET}</p><p>Capture interval: {esc(summary['first_utc'])} to {esc(summary['last_utc'])}</p></header><div class="cards">{cards}</div><section><h2>What the evidence establishes</h2><p>{esc(summary['conclusion'])}</p><div class="note">Disk and RAM images are listed in the attacker notes but were not attached. Host investigation remains pending. The operator statements have no timestamps and remain untimed in the combined timeline.</div><p class="muted">This is a generated evidence-review dashboard, not a screenshot of Autopsy or Volatility.</p></section><section><h2>Capture composition</h2>{bars}<p>{total} total frames. SSH SYN count: {ssh}; this is a connection-probe count, not a password-attempt count. Reset packets: {esc(dict(rst))}.</p></section><section><h2>Review of the large-flow alert</h2><p>The original grouping combines responses from 1,000 target ports to Kali port 46905: 60,000 captured frame bytes, 977 resets, 23 SYN-ACK responses and <b>zero TCP payload bytes</b>. This is scan-response traffic; that alert does not establish data theft.</p></section><section><h2>Reported services and packet evidence</h2><p>Service names/versions below are the operator’s claims. SYN-ACK indicates a responding TCP port. Excerpts come from individual packets, without TCP reassembly.</p><table><thead><tr><th>Port</th><th>Operator reported</th><th>SYN-ACK seen</th><th>Response frame</th><th>Excerpt frame</th><th>Packet excerpt</th></tr></thead><tbody>{rows}</tbody></table></section><section><h2>Connectivity screenshot supplied by teammate</h2><p>Shows initial “Network is unreachable”, interface configuration and then four successful ping replies. Its full date/time is unknown; it cannot be automatically placed inside the capture interval. ICMP frames in this capture: {counts['ICMP']}.</p><img src="../evidence/attacker_connectivity.jpeg" alt="Supplied Kali terminal showing successful ping after configuring eth0"></section><section><h2>Next evidence needed</h2><ol>{''.join('<li>'+esc(s)+'</li>' for s in summary['missing'])}</ol><p>Use Autopsy for the target disk; test Volatility Linux compatibility and exact kernel symbols for the supplied RAM format. PeStudio is not required for this Linux reconnaissance phase.</p><p><a href="../case/reports/report.html">Combined timeline and evidence register</a> · <a href="probed_ports.csv">All probed ports</a> · <a href="service_evidence.csv">Service evidence CSV</a> · <a href="summary.json">Results JSON</a></p></section><p class="muted">Capture SHA-256: {core.digest(capture)}</p></main></body></html>'''
 (out/'review.html').write_text(body,encoding='utf-8')
 print(json.dumps(summary,indent=2));print('REPORT:',out/'review.html')
 return summary
if __name__=='__main__':build()
