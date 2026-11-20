"""Read selected files from a monolithicSparse VMDK with an LVM ext3 root.

This narrow extractor does not repair missing grains. It stops if a requested
file touches unavailable bytes. The source image is opened read-only.
"""
import argparse
import csv
import hashlib
import math
from pathlib import Path
import struct


class MissingGrain(Exception):
    pass


class SparseVMDK:
    def __init__(self, path):
        self.path = Path(path)
        self.stream = self.path.open('rb')
        self.length = self.path.stat().st_size
        h = self.stream.read(512)
        if h[:4] != b'KDMV':
            raise ValueError('Expected monolithicSparse VMDK header')
        self.capacity, self.grain_sectors = struct.unpack_from('<QQ', h, 12)
        self.entries_per_table = struct.unpack_from('<I', h, 44)[0]
        gd_sector = struct.unpack_from('<Q', h, 56)[0]
        groups = math.ceil(self.capacity / self.grain_sectors / self.entries_per_table)
        self.stream.seek(gd_sector * 512)
        self.directory = struct.unpack('<' + 'I' * groups, self.stream.read(groups * 4))
        self.tables = {}

    def read(self, offset, count):
        out = bytearray()
        grain_bytes = self.grain_sectors * 512
        while count:
            grain = offset // grain_bytes
            group, entry = divmod(grain, self.entries_per_table)
            if group >= len(self.directory):
                raise MissingGrain(f'Outside virtual disk at {offset}')
            if group not in self.tables:
                table_sector = self.directory[group]
                if table_sector:
                    self.stream.seek(table_sector * 512)
                    raw = self.stream.read(self.entries_per_table * 4)
                    self.tables[group] = struct.unpack('<' + 'I' * self.entries_per_table, raw)
                else:
                    self.tables[group] = (0,) * self.entries_per_table
            sector = self.tables[group][entry]
            within = offset % grain_bytes
            take = min(count, grain_bytes - within)
            if sector:
                physical = sector * 512 + within
                if physical + take > self.length:
                    raise MissingGrain(f'Missing source bytes at virtual offset {offset}; physical offset {physical}')
                self.stream.seek(physical)
                chunk = self.stream.read(take)
                if len(chunk) != take:
                    raise MissingGrain(f'Short source read at physical offset {physical}')
                out.extend(chunk)
            else:
                out.extend(bytes(take))
            offset += take
            count -= take
        return bytes(out)


class Ext3:
    def __init__(self, image):
        self.image = image
        mbr = image.read(0, 512)
        if mbr[510:512] != b'\x55\xaa':
            raise ValueError('Invalid MBR')
        extended = next((struct.unpack_from('<I', mbr, 446 + i * 16 + 8)[0]
                         for i in range(4) if mbr[446 + i * 16 + 4] == 5), None)
        if extended is None:
            raise ValueError('No extended partition')
        ebr = image.read(extended * 512, 512)
        pv_start = extended + struct.unpack_from('<I', ebr, 446 + 8)[0]
        pv_head = image.read(pv_start * 512, 1024 * 1024)
        if pv_head[512:520] != b'LABELONE':
            raise ValueError('No LVM label')
        # The supplied single-PV, linear root LV has pe_start=384 sectors.
        # Parse that value from the on-disk LVM metadata rather than assume it.
        import re
        metadata = pv_head.decode('latin1', errors='replace')
        pe = re.search(r'pe_start\s*=\s*(\d+)', metadata)
        if not pe:
            raise ValueError('Cannot find LVM physical extent start')
        self.base = (pv_start + int(pe.group(1))) * 512
        sb = image.read(self.base + 1024, 1024)
        if struct.unpack_from('<H', sb, 56)[0] != 0xef53:
            raise ValueError('Root logical volume is not ext3')
        self.block_size = 1024 << struct.unpack_from('<I', sb, 24)[0]
        self.inodes_per_group = struct.unpack_from('<I', sb, 40)[0]
        self.inode_size = struct.unpack_from('<H', sb, 88)[0] or 128
        if self.block_size != 4096 or self.inode_size != 128:
            raise ValueError('Unvalidated ext3 layout')

    def block(self, number):
        return self.image.read(self.base + number * self.block_size, self.block_size)

    def inode(self, number):
        group, index = divmod(number - 1, self.inodes_per_group)
        gd = self.image.read(self.base + self.block_size + group * 32, 32)
        table = struct.unpack_from('<I', gd, 8)[0]
        raw = self.image.read(self.base + table * self.block_size + index * self.inode_size,
                              self.inode_size)
        mode = struct.unpack_from('<H', raw, 0)[0]
        size = struct.unpack_from('<I', raw, 4)[0]
        pointers = struct.unpack_from('<15I', raw, 40)
        return {'number': number, 'mode': mode, 'size': size, 'raw': raw,
                'pointers': pointers, 'mtime': struct.unpack_from('<I', raw, 16)[0]}

    def data_blocks(self, inode):
        remaining = math.ceil(inode['size'] / self.block_size)
        for block in inode['pointers'][:12]:
            if remaining <= 0:
                return
            yield block
            remaining -= 1
        for index_block in inode['pointers'][12:15]:
            if remaining <= 0:
                return
            if not index_block:
                raise ValueError('Unallocated indirect block')
            # The target logs are expected to fit in the direct/single-indirect
            # range. Refuse larger files instead of misreading double indirect.
            if index_block != inode['pointers'][12]:
                raise ValueError('Double indirect files are unsupported')
            entries = struct.unpack('<1024I', self.block(index_block))
            for block in entries:
                if remaining <= 0:
                    return
                yield block
                remaining -= 1

    def content(self, inode, max_size=32 * 1024 * 1024):
        if inode['size'] > max_size:
            raise ValueError(f'File exceeds {max_size} byte limit')
        if inode['mode'] & 0xf000 == 0xa000 and inode['size'] <= 60:
            return inode['raw'][40:40 + inode['size']]
        data = bytearray()
        for block in self.data_blocks(inode):
            data.extend(self.block(block) if block else bytes(self.block_size))
        return bytes(data[:inode['size']])

    def directory(self, inode):
        if inode['mode'] & 0xf000 != 0x4000:
            raise ValueError('Not a directory')
        data = self.content(inode)
        entries = {}
        pos = 0
        while pos + 8 <= len(data):
            number, rec_len, name_len = struct.unpack_from('<IHB', data, pos)
            if rec_len < 8 or pos + rec_len > len(data):
                break
            if number:
                entries[data[pos + 8:pos + 8 + name_len].decode('utf-8', 'replace')] = number
            pos += rec_len
        return entries

    def resolve(self, path):
        current = self.inode(2)
        for part in Path(path).parts:
            if part in ('/', '\\'):
                continue
            entries = self.directory(current)
            if part not in entries:
                raise FileNotFoundError(path)
            current = self.inode(entries[part])
        return current


TARGETS = [
    '/var/log/auth.log', '/var/log/syslog', '/var/log/vsftpd.log',
    '/var/log/apache2/access.log', '/var/log/apache2/error.log',
    '/etc/inetd.conf', '/etc/timezone',
    '/var/www/twiki/bin/system_test.sh',
]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    ap.add_argument('--output', type=Path, default=Path('disk_extraction'))
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    fs = Ext3(SparseVMDK(args.image))
    rows = []
    for path in TARGETS:
        try:
            inode = fs.resolve(path)
            content = fs.content(inode)
            destination = args.output / path.lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            rows.append([path, 'extracted', inode['number'], inode['size'], inode['mtime'],
                         hashlib.sha256(content).hexdigest(), str(destination), ''])
        except (MissingGrain, FileNotFoundError, ValueError) as exc:
            rows.append([path, 'unavailable', '', '', '', '', '', str(exc)])
    with (args.output / 'extraction_manifest.csv').open('w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        writer.writerow(['source_path', 'status', 'inode', 'size', 'mtime_unix', 'sha256',
                         'output_path', 'error'])
        writer.writerows(rows)
    with (args.output / 'directory_inventory.csv').open('w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        writer.writerow(['source_directory', 'entry_name', 'inode', 'mode', 'size', 'mtime_unix'])
        for path in ['/tmp', '/var/www/twiki/bin']:
            for name, number in fs.directory(fs.resolve(path)).items():
                if name in ('.', '..'):
                    continue
                entry = fs.inode(number)
                writer.writerow([path, name, number, oct(entry['mode']), entry['size'], entry['mtime']])
    for row in rows:
        print(row[0], row[1], row[-1])

if __name__ == '__main__':
    main()
