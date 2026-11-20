"""Import reviewed Volatility Linux process/history CSV; preserves source rows."""
import argparse,csv,json
from pathlib import Path
import forensics as core

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',required=True);p.add_argument('--file',required=True);p.add_argument('--host',default='192.168.56.20');p.add_argument('--kind',choices=['pslist','pstree','bash'],required=True);a=p.parse_args()
 try:
  with core.connect(a.case) as db:
   h=core.register(db,a.file,'Sidharth U','Linux Volatility CSV; image provenance must be registered separately')
   with Path(a.file).open(encoding='utf-8-sig',newline='') as fh:
    reader=csv.DictReader(fh)
    if 'PID' not in (reader.fieldnames or []):raise ValueError('Expected PID column; review plugin status and CSV format')
    for i,r in enumerate(reader,2):
     when=r.get('CREATION TIME',r.get('CreateTime',r.get('CommandTime','')))
     if when in ('N/A','N/A (NotApplicable)','Unreadable','-','NotApplicable'):when=''
     # A timezone-free plugin time must be reviewed, never silently assigned UTC.
     try:core.stamp(when)
     except ValueError:when=''
     core.add_event(db,dict(timestamp=when,source='host',host=a.host,event_type='linux_memory_'+a.kind,pid=r.get('PID',''),description=json.dumps(r,ensure_ascii=False),evidence_ref=f'{Path(a.file).name}:CSV row {i}; raw timestamps retained in description; unzoned times remain untimed'),h,i)
  print('Imported Linux CSV. Regenerate report with forensics.py report --case',a.case)
 except (ValueError,OSError,csv.Error) as e:p.exit(2,str(e)+'\n')
if __name__=='__main__':main()
