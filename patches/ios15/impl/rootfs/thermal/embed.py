"""Inline native N56 model; extend __DATA and keep dyld's chained format."""
import struct

from .chained import PAGE, Image, Fixup, align, new_segment_chains
from .native import METHODS, N56_CLASS, NativeImporter, discover, adr, pc_field


class Metadata:
    def __init__(self, base):
        self.base, self.cursor = base, 0
        self.data, self.slots = bytearray(PAGE), {}

    def reserve(self, size, alignment=8):
        at = align(self.cursor, alignment)
        self.cursor = at + size
        if self.cursor > PAGE:
            raise ValueError('native metadata exceeds data page')
        return self.base + at

    def write(self, address, value):
        offset = address - self.base
        if offset < 0 or offset + len(value) > self.cursor:
            raise ValueError('metadata write out of bounds')
        self.data[offset:offset + len(value)] = value

    def pointer(self, address, value):
        self.slots[address] = value if isinstance(value, Fixup) else Fixup(target=value)

    def string(self, value):
        value = value.encode() + b'\0'
        address = self.reserve(len(value), 1)
        self.write(address, value)
        return address


def section_record(name, segment, vm, size, file, flags=0, alignment=3):
    return struct.pack('<16s16sQQ8I', name.encode(), segment.encode(), vm, size, file,
                       alignment, 0, 0, flags, 0, 0, 0)


def make_class(image, metadata, methods):
    common = image.classes()['CommonProduct']
    common_meta = image.pointer(common)
    ro_common = image.pointer(common + 32) & ~7
    instance_size = image.u32(ro_common + 8)
    cls, meta, ro, meta_ro = (metadata.reserve(n) for n in (40, 40, 72, 72))
    table, name = metadata.reserve(8 + len(METHODS) * 24), metadata.string(N56_CLASS)
    metadata.pointer(cls, meta)
    metadata.pointer(cls + 8, common)
    metadata.pointer(cls + 32, ro)
    metadata.pointer(meta + 8, common_meta)
    metadata.pointer(meta + 32, meta_ro)
    metadata.write(ro, struct.pack('<4I', 0x10, instance_size, instance_size, 0))
    metadata.pointer(ro + 24, name)
    metadata.pointer(ro + 32, table)
    metadata.write(meta_ro, struct.pack('<4I', 0x11, 40, 40, 0))
    metadata.pointer(meta_ro + 24, name)
    metadata.write(table, struct.pack('<II', 24, len(METHODS)))
    selectors = image.selectors()
    for i, method in enumerate(METHODS):
        entry = table + 8 + i * 24
        metadata.pointer(entry, selectors[method][1])
        metadata.pointer(entry + 8, metadata.string(methods[method]['types']))
        metadata.pointer(entry + 16, int(methods[method]['address'], 16))
    for source, dest in ((common + 16, cls + 16), (common_meta, meta), (common_meta + 16, meta + 16)):
        f = image.fixups[source]
        if f.ordinal is None:
            raise ValueError('expected original ObjC cache/metaclass bind')
        metadata.pointer(dest, f)
    return cls


def uleb(n):
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return result


def function_starts(image, additions):
    result, previous = bytearray(), image.base
    for value in sorted(set(image.function_starts()) | set(additions)):
        result.extend(uleb(value - previous))
        previous = value
    result.append(0)
    return result


def write_image(image, metadata, code, classlist, additions):
    old_data, old_link = image.segment('__DATA'), image.segment('__LINKEDIT')
    if image.segments[-1] is not old_link or image.segments[-2] is not old_data:
        raise ValueError('unexpected data/linkedit segment order')
    data_file = old_data['file'] + old_data['size']
    code_file, code_vm = data_file + PAGE, metadata.base + PAGE
    link_file, link_vm = code_file + PAGE, code_vm + PAGE
    signature = next(p for k, p, _ in image.commands if k == 0x1d)
    sig_file, sig_size = struct.unpack_from('<II', image.data, signature + 8)
    linkedit = bytearray(image.data[old_link['file']:sig_file])
    delta = link_file - old_link['file']
    # New metadata is one more __DATA page, after the original zero-filled bss.
    r = new_segment_chains(metadata.data, metadata.base, image.base, metadata.slots)
    data_index = image.segments.index(old_data)
    old = image.chain_segments[data_index]
    _, page, fmt, segoff, maximum, count = struct.unpack_from('<IHHQIH', old)
    if page != PAGE or fmt != 6 or len(old) != 22 + 2 * count:
        raise ValueError('unsupported existing thermal DATA chain layout')
    starts = list(struct.unpack_from('<' + 'H' * count, old, 22))
    if any(v & 0x8000 and v != 0xffff for v in starts):
        raise ValueError('DATA multistarts need explicit overflow-index conversion')
    starts += [0xffff] * (old_data['size'] // PAGE - count)
    starts += [struct.unpack_from('<H', r, 22)[0]]
    extended = struct.pack('<IHHQIH', 22 + 2 * len(starts), page, fmt, segoff, maximum, len(starts))
    extended += struct.pack('<' + 'H' * len(starts), *starts)
    records = list(image.chain_segments)
    records[data_index] = extended
    records.insert(len(records) - 1, None)  # new __N56TEXT before __LINKEDIT
    chunks = {}

    def append(name, raw, alignment=8):
        linkedit.extend(bytes((-len(linkedit)) % alignment))
        chunks[name] = (link_file + len(linkedit), len(raw))
        linkedit.extend(raw)

    append('chains', image.expanded_chains(records=records))
    append('functions', function_starts(image, additions))
    # codesign reads the original entitlements/requirements from this relocated
    # blob before replacing it. Do not invent or strip signature metadata.
    append('signature', image.data[sig_file:sig_file + sig_size], 16)
    result = bytearray(image.data[:old_link['file']])
    result.extend(bytes(data_file - len(result)))
    result.extend(metadata.data)
    result.extend(code)
    result.extend(bytes(PAGE - len(code)))
    result.extend(linkedit)
    rewritten = []
    for kind, at, size in image.commands:
        raw = bytearray(image.data[at:at + size])
        if kind == 25:
            name = bytes(raw[8:24]).rstrip(b'\0').decode()
            if name == '__DATA_CONST':
                # Move the complete class list into __DATA, which the ObjC
                # runtime already scans. Do not put it in an unknown segment.
                old_classlist = image.section('__objc_classlist')
                p = old_classlist['command'] - at
                raw[p:p + 16] = b'__n56_oldclasses'.ljust(16, b'\0')
            elif name == '__DATA':
                new_size = old_data['size'] + PAGE
                struct.pack_into('<Q', raw, 32, new_size)
                struct.pack_into('<Q', raw, 48, new_size)
                struct.pack_into('<I', raw, 64, len(old_data['sections']) + 2)
                raw.extend(section_record('__n56_data', '__DATA', metadata.base,
                                          classlist - metadata.base, data_file))
                raw.extend(section_record('__objc_classlist', '__DATA', classlist,
                                          metadata.cursor - (classlist - metadata.base),
                                          data_file + classlist - metadata.base, 0x10000000))
                struct.pack_into('<I', raw, 4, len(raw))
            elif name == '__LINKEDIT':
                section = section_record('__text', '__N56TEXT', code_vm, len(code), code_file, 0x80000400, 2)
                rewritten.append(struct.pack('<II16sQQQQiiII', 25, 152, b'__N56TEXT', code_vm,
                                             PAGE, code_file, PAGE, 5, 5, 1, 0) + section)
                struct.pack_into('<4Q', raw, 24, link_vm, align(len(linkedit)), link_file, len(linkedit))
        elif kind == 2:
            for field in (8, 16):
                value = struct.unpack_from('<I', raw, field)[0]
                if value:
                    struct.pack_into('<I', raw, field, value + delta)
        elif kind == 11:
            for field in (32, 40, 48, 56, 64, 72):
                value = struct.unpack_from('<I', raw, field)[0]
                if value:
                    struct.pack_into('<I', raw, field, value + delta)
        elif kind in (0x1d, 0x26, 0x29, 0x80000033, 0x80000034):
            override = {0x1d: 'signature', 0x26: 'functions', 0x80000034: 'chains'}.get(kind)
            if override:
                struct.pack_into('<II', raw, 8, *chunks[override])
            else:
                value = struct.unpack_from('<I', raw, 8)[0]
                if value:
                    struct.pack_into('<I', raw, 8, value + delta)
        elif kind in (0x22, 0x80000022):
            raise ValueError('refusing legacy dyld-info rewrite')
        rewritten.append(raw)
    header = b''.join(rewritten)
    text_file = image.section('__text')['file']
    if 32 + len(header) > text_file:
        raise ValueError('new load commands overlap existing code')
    result[32:text_file] = bytes(text_file - 32)
    result[32:32 + len(header)] = header
    struct.pack_into('<II', result, 16, len(rewritten), len(header))
    return result


def embed(source, native_data):
    image, native = Image(source), Image(native_data)
    if image.chained_command is None:
        raise ValueError('iOS15 daemon must use LC_DYLD_CHAINED_FIXUPS')
    profile = discover(native, image)
    metadata = Metadata(image.segment('__DATA')['vm'] + image.segment('__DATA')['size'])
    importer = NativeImporter(native, image, metadata, profile)
    code, methods = bytearray(), {}
    for method in METHODS:
        at = metadata.base + PAGE + len(code)
        raw, methods[method] = importer.import_method(method, at)
        code.extend(raw)
    cls = make_class(image, metadata, methods)
    classref = metadata.reserve(8)
    metadata.pointer(classref, cls)
    factory = metadata.base + PAGE + len(code)
    # Replay exactly the first 24 bytes of the actual 15 factory.
    factory_code = bytearray(image.data[image.offset(profile['factory']):image.offset(profile['factory']) + 24])
    factory_code.extend(profile['product_compare'])  # actual native product-ID comparison
    pc = factory + len(factory_code)
    factory_code.extend(struct.pack('<I', pc_field(0x54000001, pc, pc + 12, 19, 2)))
    pc = factory + len(factory_code)
    factory_code.extend(struct.pack('<I', adr(0x10000009, pc, classref)))
    pc = factory + len(factory_code)
    factory_code.extend(struct.pack('<I', pc_field(0x14000000, pc, profile['factory_create'], 26, 2, 0)))
    pc = factory + len(factory_code)
    factory_code.extend(struct.pack('<I', pc_field(0x14000000, pc, profile['factory'] + 24, 26, 2, 0)))
    code.extend(factory_code)
    if len(code) > PAGE:
        raise ValueError('native code exceeds code page')
    old_classes = image.pointers(image.section('__objc_classlist'))
    classlist = metadata.reserve((len(old_classes) + 1) * 8)
    for i, value in enumerate([v for _, v in old_classes] + [cls]):
        metadata.pointer(classlist + i * 8, value)
    additions = [int(m['address'], 16) for m in methods.values()] + [factory]
    result = write_image(image, metadata, code, classlist, additions)
    at = image.offset(profile['factory'])
    struct.pack_into('<I', result, at, pc_field(0x14000000, profile['factory'], factory, 26, 2, 0))
    report = dict(class_name=N56_CLASS, class_address=hex(cls), factory_hook=hex(profile['factory']),
                  factory=hex(factory), factory_create=hex(profile['factory_create']),
                  sensor_writer=hex(profile['writer']), product_id=hex(profile['product_id']),
                  native_product_id_site=hex(profile['native_product_site']), primary_sensor_array=hex(profile['target_input']),
                  native_sensor_array=hex(profile['native_input']), methods=methods,
                  relocated_references=importer.relocations, native_constants=len(importer.constants),
                  original_fixups=len(image.fixups), added_fixups=len(metadata.slots),
                  imported_symbols=len(image.imports), pointer_format=6,
                  inherited_sleep=hex(profile['sleep']), native_filter_state='-1.0f,-1,-1',
                  sleep_policy='inherit iOS15 CommonProduct.canSystemSleep; retain ThermalManager and PM callback',
                  omitted='iOS12 AGGD/context telemetry tail only; no old ivar in iOS15',
                  unwind='existing unwind tables unchanged; no new compact-unwind entries')
    return result, report
