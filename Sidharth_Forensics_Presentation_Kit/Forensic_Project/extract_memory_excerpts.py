"""Recover a few exact, source-offset strings from a VirtualBox ELF memory dump.

This is a narrow string search, not a process/physical-memory reconstruction.
"""
import argparse
import csv
import hashlib
from pathlib import Path

PATTERNS = {
    'apache_nmap_probe': b'[Mon Oct 05 15:22:50 2026] [error] [client 192.168.56.10] File does not exist: /var/www/nmaplowercheck1791228170',
    'postfix_probe': b'Oct  5 15:22:38 metasploitable postfix/smtpd[4848]: connect from unknown[192.168.56.10]',
    'samba_oct6': b'[2026/10/06 01:27:43, 0] nmbd/nmbd.c:main(718)',
    'samba_oct11': b'[2026/10/11 03:56:05, 0] nmbd/nmbd.c:main(718)',
}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('memory', type=Path)
    ap.add_argument('--output', type=Path, default=Path('evidence/memory_excerpts.csv'))
    args = ap.parse_args()
    hits = {name: [] for name in PATTERNS}
    sha = hashlib.sha256()
    with args.memory.open('rb') as stream:
        offset = 0
        tail = b''
        while chunk := stream.read(4 * 1024 * 1024):
            sha.update(chunk)
            data = tail + chunk
            base = offset - len(tail)
            for name, pattern in PATTERNS.items():
                start = 0
                while True:
                    index = data.find(pattern, start)
                    if index < 0:
                        break
                    location = base + index
                    if location >= offset or location + len(pattern) > offset:
                        hits[name].append((location, pattern.decode('ascii')))
                    start = index + 1
            offset += len(chunk)
            tail = data[-256:]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        writer.writerow(['ram_sha256','byte_offset','finding','exact_ascii_excerpt','limitation'])
        for name, entries in hits.items():
            for position, excerpt in entries:
                writer.writerow([sha.hexdigest(), position, name, excerpt,
                                 'Recovered string only; timezone and process context unverified'])
    print('RAM SHA-256:', sha.hexdigest())
    print('Matches:', {name: len(entries) for name, entries in hits.items()})

if __name__ == '__main__':
    main()
