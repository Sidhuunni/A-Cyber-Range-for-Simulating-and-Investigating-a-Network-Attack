import csv,json,sqlite3,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import forensics as f

class PipelineTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.case=self.root/'case';self.assertEqual(f.main(['init','--case',str(self.case)]),0)
 def tearDown(self):self.tmp.cleanup()
 def csv(self,rows):
  p=self.root/'events.csv';f.export_csv(p,f.FIELDS,[{k:r.get(k,'') for k in f.FIELDS} for r in rows]);return p
 def event(self,**kw):return dict(timestamp='2026-10-10T08:00:00Z',source='host',description='socket observed',evidence_ref='netscan.csv row 2',src_ip='10.0.0.2',dst_ip='10.0.0.1',src_port='5000',dst_port='80')|kw
 def test_timezone(self):self.assertEqual(f.stamp('2026-10-10T13:30:00+05:30'),f.stamp('2026-10-10T08:00:00Z'))
 def test_naive_rejected_and_transaction_rollback(self):
  path=self.csv([self.event(),self.event(timestamp='2026-10-10T08:00:00')]);self.assertEqual(f.main(['import-events','--case',str(self.case),'--file',str(path)]),2)
  with f.connect(self.case) as db:self.assertEqual(db.execute('select count(*) from events').fetchone()[0],0)
 def test_duplicate_import(self):
  p=self.csv([self.event()])
  for _ in range(2):self.assertEqual(f.main(['import-events','--case',str(self.case),'--file',str(p)]),0)
  with f.connect(self.case) as db:self.assertEqual(db.execute('select count(*) from events').fetchone()[0],1)
 def test_untimed_and_escaped_html(self):
  p=self.csv([self.event(timestamp='',description='<script>alert(1)</script>')]);f.main(['import-events','--case',str(self.case),'--file',str(p)]);f.main(['report','--case',str(self.case)])
  text=(self.case/'reports/report.html').read_text();self.assertIn('&lt;script&gt;',text);self.assertNotIn('<script>alert(1)',text)
  rows=list(csv.DictReader((self.case/'reports/timeline.csv').read_text().splitlines()));self.assertEqual(rows[0]['timestamp'],'')
 def test_matching_rejects_wrong_port_and_far_time(self):
  with f.connect(self.case) as db:
   f.add_event(db,self.event(),'a',1)
   for i,(t,sp) in enumerate([(1791619200,5000),(1791619200,5001),(1791629200,5000)]):
    f.add_packet(db,dict(time=t,src='10.0.0.2',dst='10.0.0.1',proto='TCP',sport=sp,dport=80,length=60,is_syn=1),'b',i)
   f.report(db,self.case,60)
  links=list(csv.DictReader((self.case/'reports/correlations.csv').read_text().splitlines()));self.assertEqual(len(links),1);self.assertEqual(links[0]['packet_count'],'1')
 def test_readonly_sqlite_compatibility(self):
  p=self.root/'traffic.db'
  with sqlite3.connect(p) as db:
   db.execute('create table packets(time,src,dst,proto,sport,dport,length,is_syn)');db.execute("insert into packets values(1,'a','b','TCP',123,22,60,1)")
  old=f.digest(p);self.assertEqual(f.main(['import-network','--case',str(self.case),'--file',str(p)]),0);self.assertEqual(f.digest(p),old)
 def test_evidence_tamper_detected(self):
  p=self.root/'e.txt';p.write_text('original');f.main(['register','--case',str(self.case),'--file',str(p),'--note','test']);p.write_text('changed');self.assertEqual(f.main(['verify','--case',str(self.case)]),1)
 def test_empty_capture_db(self):
  p=self.root/'empty.db'
  with sqlite3.connect(p) as db:db.execute('create table packets(time,src,dst,proto,sport,dport,length,is_syn)')
  self.assertEqual(f.main(['import-network','--case',str(self.case),'--file',str(p)]),0);self.assertEqual(f.main(['report','--case',str(self.case)]),0)
 def test_volatility_netscan(self):
  p=self.root/'netscan.csv';f.export_csv(p,['PID','LocalAddr','LocalPort','ForeignAddr','ForeignPort','Created'],[dict(PID=42,LocalAddr='10.0.0.2',LocalPort=5000,ForeignAddr='10.0.0.1',ForeignPort=80,Created='2026-10-10 08:00:00+00:00')])
  self.assertEqual(f.main(['import-vol','--case',str(self.case),'--file',str(p),'--kind','netscan','--host','10.0.0.2']),0)
 def test_missing_file(self):self.assertEqual(f.main(['register','--case',str(self.case),'--file',str(self.root/'absent'),'--note','test']),2)
if __name__=='__main__':unittest.main()
