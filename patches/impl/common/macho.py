"""Read classic split prelinked Mach-O images, including plist IDREFs."""
from pathlib import Path
import base64
import struct
import subprocess
import xml.etree.ElementTree as ET

class Kernel:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.segs = self.segments(0)
        pi = next(s for s in self.segs if s['name'] == '__PRELINK_INFO')
        self.xml = self.data[pi['fo']:pi['fo'] + pi['fs']].rstrip(b'\0')
        root = ET.fromstring(self.xml[self.xml.find(b'<dict>'):self.xml.rfind(b'</dict>') + 7])
        self.ids = {e.attrib['ID']: e for e in root.iter() if 'ID' in e.attrib}
        self.info = self.decode(root)
        self.kexts = {e['CFBundleIdentifier']: e for e in self.info['_PrelinkInfoDictionary']}

    def decode(self, e):
        if 'IDREF' in e.attrib:
            return self.decode(self.ids[e.attrib['IDREF']])
        children = list(e)
        if e.tag == 'dict':
            return {children[i].text: self.decode(children[i + 1]) for i in range(0, len(children), 2)}
        if e.tag == 'array':
            return [self.decode(c) for c in children]
        if e.tag in ('key', 'string'):
            return e.text or ''
        if e.tag == 'integer':
            t = e.text or '0'
            return int(t, 16 if t.lower().startswith('0x') else 10)
        if e.tag in ('true', 'false'):
            return e.tag == 'true'
        if e.tag == 'data':
            return base64.b64decode(e.text or '')
        raise ValueError(f'unsupported plist element {e.tag}')

    def commands(self, header=0):
        if struct.unpack_from('<I', self.data, header)[0] != 0xfeedfacf:
            raise ValueError('not a 64-bit Mach-O')
        n, size = struct.unpack_from('<II', self.data, header + 16)
        p = header + 32
        commands = []
        for _ in range(n):
            cmd, length = struct.unpack_from('<II', self.data, p)
            if length < 8 or p + length > header + 32 + size:
                raise ValueError('invalid Mach-O command size')
            commands.append((cmd, self.data[p:p + length]))
            p += length
        if p != header + 32 + size:
            raise ValueError('load-command size mismatch')
        return commands

    def segments(self, header=0):
        out = []
        for cmd, raw in self.commands(header):
            if cmd != 25:
                continue
            vm, vs, fo, fs, maxp, initp, nsect, flags = struct.unpack_from('<QQQQiiII', raw, 24)
            sections = []
            for i in range(nsect):
                s = raw[72 + i * 80:152 + i * 80]
                sections.append(dict(name=s[:16].rstrip(b'\0').decode(),
                                     addr=struct.unpack_from('<Q', s, 32)[0],
                                     size=struct.unpack_from('<Q', s, 40)[0],
                                     offset=struct.unpack_from('<I', s, 48)[0], raw=s))
            out.append(dict(name=raw[8:24].rstrip(b'\0').decode(), vm=vm, vs=vs,
                            fo=fo, fs=fs, maxp=maxp, prot=initp, sections=sections, raw=raw))
        return out

    def offset(self, va, size=1):
        for s in self.segs:
            if s['vm'] <= va and va + size <= s['vm'] + s['fs']:
                return s['fo'] + va - s['vm']
        raise ValueError(f'address not file-backed: {va:#x}+{size:#x}')

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def ksegments(self, bundle):
        return self.segments(self.offset(self.kexts[bundle]['_PrelinkExecutableLoadAddr']))

    def symbols(self):
        process = subprocess.run(['nm', '-n', str(self.path)], capture_output=True, text=True, check=True)
        out = {}
        for line in process.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3:
                try:
                    out[fields[2]] = int(fields[0], 16)
                except ValueError:
                    pass
        return out

    def slide_slots(self):
        blob = self.info['_PrelinkLinkKASLROffsets']
        words = struct.unpack('<' + 'I' * (len(blob) // 4), blob)
        if words[0] != len(words) - 1:
            raise ValueError('KASLR count mismatch')
        base = next(s['vm'] for s in self.segs if s['name'] == '__PRELINK_TEXT')
        return [base + off for off in words[1:]]

    def claims(self):
        out = []
        for bundle, info in self.kexts.items():
            if '_PrelinkExecutableLoadAddr' not in info:
                continue
            if '_PrelinkInterfaceUUID' in info:
                # KPI interface headers are coalesced 0x80-byte records; their
                # original LINKEDIT commands/size fields no longer describe mapped storage.
                address = info['_PrelinkExecutableLoadAddr']
                out.append((address, address + 0x80, bundle + '/interface header'))
                continue
            for s in self.ksegments(bundle):
                if s['vs']:
                    out.append((s['vm'], s['vm'] + s['vs'], bundle + '/' + s['name']))
        return out
