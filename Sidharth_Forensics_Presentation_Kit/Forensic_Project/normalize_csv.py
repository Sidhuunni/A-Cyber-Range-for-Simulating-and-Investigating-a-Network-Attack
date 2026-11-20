"""Explicit column mapping for Autopsy/other exports. Preserves row references.
No guessing of timestamp meaning or timezone; inspect original tool export.
"""
import argparse,csv,json
from pathlib import Path
from forensics import FIELDS,export_csv,stamp

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input');p.add_argument('--map',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();out=Path(a.out)
    if out.exists():p.error('Choose a new output filename')
    cfg=json.loads(Path(a.map).read_text(encoding='utf-8-sig'))
    mapping=cfg.get('columns',{});constants=cfg.get('constants',{})
    if not set(mapping)|set(constants)<=set(FIELDS):p.error('Unknown output field in map')
    rows=[]
    with Path(a.input).open(encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f)
        missing=set(mapping.values())-set(reader.fieldnames or [])
        if missing:p.error('CSV columns missing: '+str(missing))
        for i,r in enumerate(reader,2):
            e={k:'' for k in FIELDS};e.update(constants);e.update({k:r[v] for k,v in mapping.items()})
            try:stamp(e['timestamp'])
            except ValueError:p.error(f'Row {i}: timestamp must be ISO8601 with offset or epoch. Make a documented normalized copy first.')
            e['evidence_ref']=f'{Path(a.input).name}:CSV row {i}; '+e['evidence_ref']
            if not e['description'] or e['source'] not in ('host','network','attacker'):p.error(f'Row {i}: need description and valid source')
            rows.append(e)
    export_csv(out,FIELDS,rows);print('Wrote',len(rows),'rows to',out)
if __name__=='__main__':main()
