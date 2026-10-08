#!/usr/bin/env python3
"""Extract selected full-OTA partitions using verified HTTPS byte ranges.

Only replacement/zero operations are supported; never applies an OTA to a phone.
"""
import argparse
import bz2
import hashlib
import io
import json
import lzma
from pathlib import Path
import struct
import time
import urllib.request
import zipfile


def varint(data, pos):
    value = shift = 0
    while pos < len(data) and shift < 70:
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
        shift += 7
    raise ValueError('Invalid protobuf varint')


def fields(data):
    result = {}
    pos = 0
    while pos < len(data):
        tag, pos = varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 2:
            length, pos = varint(data, pos)
            value = data[pos:pos + length]
            if len(value) != length:
                raise ValueError('Truncated protobuf')
            pos += length
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            value = data[pos:pos + length]
            pos += length
        else:
            raise ValueError(f'Unsupported wire type {wire}')
        result.setdefault(number, []).append(value)
    return result


def first(values, number, default=None):
    return values.get(number, [default])[0]


class RangeFile(io.RawIOBase):
    def __init__(self, url, size):
        self.url, self.size, self.pos, self.bytes_fetched = url, size, 0, 0
        self.cache = {}

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = offset + (self.pos if whence == 1 else self.size if whence == 2 else 0)
        if self.pos < 0:
            raise ValueError('Negative seek')
        return self.pos

    def fetch(self, offset, length):
        if length == 0:
            return b''
        if offset < 0 or offset + length > self.size:
            raise ValueError('Range outside file')
        key = (offset, length)
        if key in self.cache:
            return self.cache[key]
        end = offset + length - 1
        expected = f'bytes {offset}-{end}/{self.size}'
        for attempt in range(4):
            try:
                req = urllib.request.Request(self.url, headers={
                    'Range': f'bytes={offset}-{end}', 'User-Agent': 'Mozilla/5.0',
                    'Accept-Encoding': 'identity'})
                with urllib.request.urlopen(req, timeout=45) as response:
                    if response.status != 206 or response.headers.get('Content-Range') != expected:
                        raise ValueError(f'Unexpected range response: {response.status}, '
                                         f'{response.headers.get("Content-Range")}')
                    data = response.read(length + 1)
                if len(data) != length:
                    raise ValueError(f'Truncated range: {len(data)} != {length}')
                self.bytes_fetched += length
                if length < 4 * 1024 * 1024:
                    self.cache[key] = data
                return data
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(attempt + 1)

    def read(self, size=-1):
        size = min(self.size - self.pos, self.size if size < 0 else size)
        data = self.fetch(self.pos, size)
        self.pos += size
        return data


def probe_size(url):
    """用 HEAD 或单字节 Range 问出远端总长度，省掉手填 --size。"""
    head = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(head, timeout=30) as response:
            length = response.headers.get('Content-Length')
            if length and response.headers.get('Accept-Ranges', '').lower() != 'none':
                return int(length)
    except Exception:
        pass
    probe = urllib.request.Request(
        url, headers={'User-Agent': 'Mozilla/5.0', 'Range': 'bytes=0-0'})
    with urllib.request.urlopen(probe, timeout=30) as response:
        if response.status != 206:
            raise SystemExit('remote does not honour Range requests; download the zip and pass a file:// URL')
        content_range = response.headers.get('Content-Range', '')
        total = content_range.rsplit('/', 1)[-1].strip() if '/' in content_range else ''
        if not total.isdigit():
            raise SystemExit(f'cannot determine size from Content-Range: {content_range!r}; pass --size')
        return int(total)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--size', type=int,
                        help='OTA total bytes; probed automatically when omitted')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--partition', action='append', default=[])
    parser.add_argument('--list', action='store_true',
                        help='list every partition in the manifest, extract nothing')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    size = args.size or probe_size(args.url)
    print(f'ota size: {size} bytes')
    remote = RangeFile(args.url, size)
    with zipfile.ZipFile(remote) as archive:
        entries = [{'name': x.filename, 'size': x.file_size, 'compression': x.compress_type}
                   for x in archive.infolist()]
        (args.out / 'zip_contents.json').write_text(json.dumps(entries, indent=2))
        payload = archive.getinfo('payload.bin')
        if payload.compress_type != zipfile.ZIP_STORED:
            raise ValueError('payload.bin must be ZIP_STORED for remote extraction')
        header = remote.fetch(payload.header_offset, 30)
        if header[:4] != b'PK\x03\x04':
            raise ValueError('Invalid ZIP local header')
        name_len, extra_len = struct.unpack_from('<HH', header, 26)
        payload_start = payload.header_offset + 30 + name_len + extra_len
        for name in ('META-INF/com/android/metadata', 'payload_properties.txt'):
            if name in archive.namelist():
                (args.out / name.rsplit('/', 1)[-1]).write_bytes(archive.read(name))
    header = remote.fetch(payload_start, 24)
    magic, version, manifest_size, signature_size = struct.unpack('>4sQQI', header)
    if magic != b'CrAU' or version != 2 or manifest_size > 32 * 1024 * 1024:
        raise ValueError('Unexpected payload header')
    manifest_bytes = remote.fetch(payload_start + 24, manifest_size)
    (args.out / 'payload_manifest.pb').write_bytes(manifest_bytes)
    manifest = fields(manifest_bytes)
    block_size = first(manifest, 3, 4096)
    data_start = payload_start + 24 + manifest_size + signature_size
    selected = args.partition or ['boot']
    evidence = {'ota_url': args.url, 'ota_size': size,
                'payload_offset': payload_start, 'payload_size': payload.file_size,
                'payload_version': version, 'manifest_size': manifest_size,
                'metadata_signature_size': signature_size,
                'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                'block_size': block_size, 'partitions': [], 'extracted': []}
    for raw in manifest.get(13, []):
        partition = fields(raw)
        name = first(partition, 1).decode()
        info = fields(first(partition, 7, b''))
        operations = [fields(op) for op in partition.get(8, [])]
        summary = {'name': name, 'size': first(info, 1),
                   'sha256': first(info, 2, b'').hex(), 'operation_count': len(operations),
                   'operation_types': sorted(set(first(op, 1) for op in operations))}
        evidence['partitions'].append(summary)
        if args.list:
            print(f"{name:<20} {first(info, 1) or 0:>12} bytes  "
                  f"ops={len(operations)} types={summary['operation_types']}")
            continue
        if name not in selected:
            continue
        if any(first(op, 1) not in (0, 1, 6, 7, 8, 14) for op in operations):
            raise ValueError(f'{name} requires unsupported/delta operations')
        output = args.out / f'{name}.img'
        print(f'Extracting {name}: {summary["size"]} bytes, {len(operations)} operations', flush=True)
        op_evidence = []
        with output.open('w+b') as stream:
            stream.truncate(summary['size'])
            for index, op in enumerate(operations):
                kind, length, offset = first(op, 1), first(op, 3, 0), first(op, 2, 0)
                extents = [fields(e) for e in op.get(6, [])]
                dest_size = sum(first(e, 2) * block_size for e in extents)
                data = remote.fetch(data_start + offset, length) if length else b''
                digest = hashlib.sha256(data).digest()
                expected = first(op, 8)
                if expected and digest != expected:
                    raise ValueError(f'{name} operation {index} data SHA256 mismatch')
                if kind == 1:
                    data = bz2.decompress(data)
                elif kind == 8:
                    data = lzma.decompress(data)
                elif kind == 14:
                    import zstandard
                    data = zstandard.ZstdDecompressor().decompress(data, max_output_size=dest_size)
                elif kind in (6, 7):
                    data = bytes(dest_size)
                if len(data) > dest_size:
                    raise ValueError('Decoded operation exceeds destination')
                data += bytes(dest_size - len(data))
                cursor = 0
                for extent in extents:
                    start, count = first(extent, 1), first(extent, 2)
                    if start == (1 << 64) - 1 or (start + count) * block_size > summary['size']:
                        raise ValueError('Invalid destination extent')
                    amount = count * block_size
                    stream.seek(start * block_size)
                    stream.write(data[cursor:cursor + amount])
                    cursor += amount
                op_evidence.append({'index': index, 'type': kind, 'data_offset': offset,
                                    'data_length': length, 'data_sha256': digest.hex(),
                                    'expected_data_sha256': expected.hex() if expected else None,
                                    'hash_verified': bool(expected)})
                if index % 5 == 0 or index == len(operations) - 1:
                    print(f'  operation {index + 1}/{len(operations)} complete', flush=True)
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        if digest != summary['sha256']:
            raise ValueError(f'{name} partition SHA256 mismatch: {digest}')
        evidence['extracted'].append({**summary, 'file': output.name,
                                      'partition_hash_verified': True, 'operations': op_evidence})
        print(f'{name} SHA256 verified: {digest}', flush=True)
    found = {p['name'] for p in evidence['extracted']}
    if found != set(selected):
        raise ValueError(f'Missing partitions: {set(selected) - found}')
    evidence['http_bytes_downloaded'] = remote.bytes_fetched
    (args.out / 'extraction_evidence.json').write_text(json.dumps(evidence, indent=2))
    print(f'Done; fetched {remote.bytes_fetched / 1024 / 1024:.2f} MiB', flush=True)


if __name__ == '__main__':
    main()
