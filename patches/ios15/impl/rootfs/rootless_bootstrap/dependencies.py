"""Offline Debian status closure audit; no APT execution or fabricated packages."""
import re


def paragraphs(text):
    result = []
    for section in re.split(r'\n\s*\n', text.strip()):
        row, key = {}, None
        for line in section.splitlines():
            if line.startswith((' ', '\t')) and key:
                row[key] += ' ' + line.strip()
            elif ':' in line:
                key, value = line.split(':', 1)
                row[key] = value.strip()
        if row:
            result.append(row)
    return result


def _part_compare(a, b):
    def order(c):
        return -1 if c == '~' else 0 if not c else ord(c) if c.isalpha() else ord(c) + 256
    while a or b:
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            ca = a[0] if a and not a[0].isdigit() else ''
            cb = b[0] if b and not b[0].isdigit() else ''
            if order(ca) != order(cb):
                return -1 if order(ca) < order(cb) else 1
            if ca: a = a[1:]
            if cb: b = b[1:]
        da = re.match(r'\d*', a).group().lstrip('0')
        db = re.match(r'\d*', b).group().lstrip('0')
        a = re.sub(r'^\d*', '', a)
        b = re.sub(r'^\d*', '', b)
        if len(da) != len(db): return -1 if len(da) < len(db) else 1
        if da != db: return -1 if da < db else 1
    return 0


def compare(a, b):
    def split(v):
        epoch, v = v.split(':', 1) if ':' in v else ('0', v)
        upstream, revision = v.rsplit('-', 1) if '-' in v else (v, '0')
        return int(epoch), upstream, revision
    ea, ua, ra = split(a); eb, ub, rb = split(b)
    return ((ea > eb) - (ea < eb)) or _part_compare(ua, ub) or _part_compare(ra, rb)


def audit(status, *, architecture='iphoneos-arm64'):
    rows = paragraphs(status)
    by_name = {r['Package']: r for r in rows if 'Package' in r}
    available = {name: [r.get('Version', '')] for name, r in by_name.items()}
    for row in rows:
        for provide in row.get('Provides', '').split(','):
            match = re.fullmatch(r'\s*([a-z0-9.+-]+)(?:\s*\(=\s*([^\)]+)\))?\s*', provide)
            if match:
                available.setdefault(match[1], []).append(match[2] or '')
    unresolved = []
    for row in rows:
        if row.get('Architecture') not in (architecture, 'all'):
            raise ValueError('unsupported Debian architecture: ' + str(row.get('Architecture')))
        for field in ('Pre-Depends', 'Depends'):
            for clause in row.get(field, '').split(','):
                if not clause.strip(): continue
                satisfied = False
                for alternative in clause.split('|'):
                    match = re.fullmatch(rf'\s*([a-z0-9.+-]+)(?::(?:any|native|{re.escape(architecture)}))?'
                                         r'(?:\s*\((<<|<=|=|>=|>>)\s*([^\)]+)\))?\s*', alternative)
                    if not match:
                        raise ValueError('unsupported dependency grammar: ' + alternative)
                    name, op, version = match.groups()
                    for found in available.get(name, []):
                        cmp = compare(found, version) if op and found else None
                        if not op or cmp is not None and {'<<': cmp < 0, '<=': cmp <= 0, '=': cmp == 0,
                                                         '>=': cmp >= 0, '>>': cmp > 0}[op]:
                            satisfied = True
                if not satisfied:
                    unresolved.append(dict(package=row['Package'], field=field, dependency=clause.strip()))
    return dict(package_count=len(rows), architectures=sorted({r['Architecture'] for r in rows}),
                status_counts={s: sum(r.get('Status') == s for r in rows) for s in sorted({r.get('Status') for r in rows})},
                unresolved=unresolved, closure_satisfied=not unresolved,
                postinst_executed=False, firmware_virtual_packages_generated=False)
