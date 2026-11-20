import csv,json,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import forensics as f
ROOT=Path(__file__).resolve().parents[1]
class LinuxUpdate(unittest.TestCase):
 def test_real_capture_counts_and_alert(self):
  with tempfile.TemporaryDirectory() as td:
   self.assertEqual(f.main(['init','--case',td]),0)
   args=['import-network','--case',td,'--file',str(ROOT/'evidence/lab_recon_capture.pcapng')]
   for _ in range(2):self.assertEqual(f.main(args),0)
   with f.connect(td) as db:
    self.assertEqual(db.execute('SELECT COUNT(*) FROM packets').fetchone()[0],2568)
    self.assertEqual(db.execute("SELECT COUNT(DISTINCT dport) FROM packets WHERE src='192.168.56.10' AND dst='192.168.56.20' AND is_syn=1").fetchone()[0],1000)
    f.report(db,td,60)
   self.assertIn('Possible port scan',(Path(td)/'reports/timeline.csv').read_text())
 def test_linux_import_untimed_preserved(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);f.main(['init','--case',td]);f.export_csv(p/'p.csv',['PID','COMM','CREATION TIME'],[{'PID':'123','COMM':'sshd','CREATION TIME':'2008-10-01 10:00:00'}])
   r=subprocess.run([sys.executable,str(ROOT/'import_linux_csv.py'),'--case',td,'--file',str(p/'p.csv'),'--kind','pslist'],capture_output=True)
   self.assertEqual(r.returncode,0,r.stderr)
   with f.connect(td) as db:
    e=db.execute('select ts,description from events').fetchone();self.assertIsNone(e['ts']);self.assertIn('2008-10-01',e['description'])
 def test_linux_runner_failure_records(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);f.main(['init','--case',td]);(p/'ram.elf').write_bytes(b'fixture');(p/'fake_vol.py').write_text('import sys\nprint("unsupported fixture",file=sys.stderr)\nsys.exit(2)\n')
   self.assertEqual(f.main(['run-vol','--case',td,'--memory',str(p/'ram.elf'),'--vol',str(p/'fake_vol.py'),'--os','linux']),1)
   status=json.loads(next((p/'volatility').rglob('run_status.json')).read_text());self.assertTrue(all(x['returncode']==2 for x in status));self.assertIn('linux.pslist.PsList',[x['plugin'] for x in status])
if __name__=='__main__':unittest.main()
