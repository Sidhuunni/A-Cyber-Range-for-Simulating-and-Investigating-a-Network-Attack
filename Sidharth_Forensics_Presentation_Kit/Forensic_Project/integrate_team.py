"""Import one lab run's team evidence into a new or matching forensic case.

This does not infer compromise. Evidence files stay at their original paths;
keep those files available for verification and archive them separately.
"""
import argparse
import csv
import json
from pathlib import Path
import sys

import forensics as core


def check_events(path, expected):
    with Path(path).open(encoding='utf-8-sig', newline='') as fh:
        reader = csv.DictReader(fh)
        if not set(core.FIELDS) <= set(reader.fieldnames or []):
            raise ValueError(f'{path}: use the full templates/events.csv header')
        for line, row in enumerate(reader, 2):
            if row['source'] != expected:
                raise ValueError(f'{path}: row {line}: source must be {expected}')
            if not row['description'] or not row['evidence_ref']:
                raise ValueError(f'{path}: row {line}: description and evidence_ref required')
            core.stamp(row['timestamp'])  # Blank is allowed; naive dates are not.


def run(args):
    case = Path(args.case)
    for path, kind in ((args.attacker_events, 'attacker'),
                       (args.host_events, 'host'),
                       (args.network_events, 'network')):
        if path:
            check_events(path, kind)
    if not case.joinpath('case.json').exists():
        if case.exists() and any(case.iterdir()):
            raise ValueError('Case directory exists without a valid case; choose another directory')
        if core.main(['init', '--case', str(case), '--name', args.name]):
            raise ValueError('Case initialization failed')
    with core.connect(case) as db:
        if args.capture:
            capture_hash = core.digest(args.capture)
            old = {r[0] for r in db.execute('SELECT DISTINCT evidence_sha256 FROM packets')}
            if old and old != {capture_hash}:
                raise ValueError('Different capture already imported. Use a new case for a different run.')
            core.load_network(db, args.capture, args.collector)
        for path, label in ((args.attacker_events, 'attacker event log'),
                            (args.host_events, 'reviewed host observations'),
                            (args.network_events, 'network alert export')):
            if path:
                core.load_csv(db, path, args.collector)
        for path in args.disk:
            core.register(db, path, args.collector, 'Target disk descriptor/extent; acquisition details in templates/acquisition.csv')
        if args.ram:
            core.register(db, args.ram, args.collector, 'Target guest RAM; acquisition details in templates/acquisition.csv')
        for path in args.extra_evidence:
            core.register(db, path, args.collector, 'Supporting original evidence; see team handoff')
        core.report(db, case, args.window)
        summary = json.loads((case/'reports'/'summary.json').read_text())
        summary['capture_sha256'] = args.capture and core.digest(args.capture)
        summary['registered_files'] = db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]
        summary['host_image_supplied_this_call'] = bool(args.disk or args.ram)
        summary['interpretation'] = 'Candidate links are time/endpoint matches; manually verify clock offsets and original artifacts.'
        (case/'reports'/'team_integration_status.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', default='case_final', help='Separate case directory for one run')
    p.add_argument('--name', default='Cyber range final run')
    p.add_argument('--capture', help='Vedh PCAP/PCAPNG or SQLite packets database')
    p.add_argument('--attacker-events', help='Prashnik event CSV in templates/events.csv format')
    p.add_argument('--host-events', help='Reviewed Autopsy/Volatility events in same format')
    p.add_argument('--network-events', help='Reviewed network alerts in same format')
    p.add_argument('--disk', action='append', default=[], help='Repeat for each target disk descriptor and extent')
    p.add_argument('--ram', help='Target guest RAM image')
    p.add_argument('--extra-evidence', action='append', default=[], help='Repeat for raw logs, hashes, or test files')
    p.add_argument('--collector', default='Sidharth U')
    p.add_argument('--window', type=int, default=60, help='Candidate correlation window, seconds')
    args = p.parse_args(argv)
    if not any((args.capture,args.attacker_events,args.host_events,args.network_events,args.disk,args.ram,args.extra_evidence)):
        p.error('Provide at least one evidence file')
    if not 0 <= args.window <= 86400:
        p.error('--window must be 0..86400')
    try:
        return run(args)
    except (OSError, ValueError, csv.Error) as e:
        print('ERROR:', e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
