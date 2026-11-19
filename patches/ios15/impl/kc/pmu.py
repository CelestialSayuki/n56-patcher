"""Fail-closed, offline D2186 profile for the J96 iOS 15 D2207 PMU.

Only hardware constants are imported from shared; no iOS 14 locators/offsets.
Only the stale PMU watchdog personality is made non-matching. AppleARMWatchdogTimer
(wdt,s5l8960x) is left untouched: it is what publishes IOWatchdog for watchdogd,
exactly like iOS 14's AppleS5L8960XWatchDogTimer. RTC and the eight 14-byte event
lengths are retained. This does not claim to disable the physical hardware watchdog.
AppleSamsungSerial's four UFCON selection immediates are set to the N56 native
values (M8 UART); all other drivers' executable code is outside this patch.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re
import struct
import xml.etree.ElementTree as ET

from patches.shared.impl.kc import pmu_d2186 as hardware

PMU = "com.apple.driver.AppleD2207PMU"
ARM_WDT = "com.apple.driver.AppleARMWatchdogTimer"
RAIL = (0x71005AFF, 0x71004EFF)  # cmp w23, #22 / #19, not iOS 14's w21
MASK = (hardware.MASK_OLD, hardware.MASK_NEW)
MASK_SHIFT = 0x9AD92508  # lsr x8, x8, x25
BOOST_SUB = 0xD1003B29  # sub x9, x25, #14
SETLDO_HEAD = (0xD10243FF, 0xA9036FFC, 0xA90467FA, 0xA9055FF8,
               0xA90657F6, 0xA9074FF4, 0xA9087BFD, 0x910203FD)
# iOS 15: stack byte at sp+0xf; cbz/cmp w23 precede mode-2 (not +0x34).
GPIO_BLOCK = (hardware.GPIO_LEVELS_OLD[0], 0x0A090108, 0x39003FE8,
              0x34000137, 0x71000AFF, 0x540000A0, 0x710006FF,
              0x54000161, 0x321F0108, 0x14000002, hardware.GPIO_MODE2_OLD,
              0x39003FE8, 0x370001F5)
GPIO_BLOCK_NEW = (hardware.GPIO_LEVELS_NEW[0], *GPIO_BLOCK[1:10],
                  hardware.GPIO_MODE2_NEW, *GPIO_BLOCK[11:])
PERSONALITIES = (
    (PMU, "PMU", "IONameMatch", "pmu,d2207", "pmu,d2186"),
    (PMU, "PMUWatchDogTimer", "IOProviderClass", "AppleD2207PMU", "AppleD2207PMX"),
)
SERIAL = "com.apple.driver.AppleSamsungSerial"
# UFCON selection in AppleSamsungSerial (N56 native: 0x1f1 / 0x1c1 / 0x1c1, mask 0xff).
# The word at +28 (mov wN, #0) changes register between iOS 14 and 15 and is a wildcard.
UART_FIFO = ((0, 0x52804E28, 0x52803E28),    # mov w8, #0x271 -> #0x1f1
             (16, 0x52804C28, 0x52803828),   # mov w8, #0x261 -> #0x1c1
             (20, 0x52804829, 0x52803829),   # mov w9, #0x241 -> #0x1c1
             (36, 0x52800E2A, 0x52801FEA))   # mov w10, #0x71 -> #0xff
UART_CONTEXT = {4: 0x14000006, 8: 0x39441A68, 12: 0x7100011F, 24: 0x1A880128,
                32: 0xB9410A69, 40: 0x0A0A010A, 44: 0x7100013F, 48: 0x1A880149}
UART_SPAN = 52


class PatchError(ValueError):
    """Unexpected, ambiguous, partially patched or corrupt input; write nothing."""


def words(values):
    return struct.pack("<" + "I" * len(values), *values)


def word(data, offset):
    if offset < 0 or offset + 4 > len(data) or offset % 4:
        raise PatchError(f"invalid instruction offset {offset:#x}")
    return struct.unpack_from("<I", data, offset)[0]


def hits(data, signature, aligned=True):
    result, offset = [], data.find(signature)
    while offset >= 0:
        if not aligned or offset % 4 == 0:
            result.append(offset)
        offset = data.find(signature, offset + 1)
    return result


def unique(locations, label, count=1):
    if len(locations) != count:
        raise PatchError(f"{label}: expected {count} scoped matches, found {len(locations)}")
    return locations[0] if count == 1 else locations


def variants(data, before, after, label, count=1):
    return unique(sorted(set(hits(data, before) + hits(data, after))), label, count)


def branch_target(data, offset, conditional=True):
    instruction = word(data, offset)
    if conditional:
        if instruction & 0xFF00001F != 0x54000008:
            raise PatchError("expected b.hi")
        immediate, bits = (instruction >> 5) & 0x7FFFF, 19
    else:
        if instruction & 0xFC000000 != 0x14000000:
            raise PatchError("expected b")
        immediate, bits = instruction & 0x3FFFFFF, 26
    if immediate & (1 << (bits - 1)):
        immediate -= 1 << bits
    return offset + immediate * 4


def table_xrefs(code, code_va, table_va):
    """Decode ADRP + ADD in the PMU executable segment only, before and after."""
    result = []
    for offset in range(0, len(code) - 8, 4):
        adrp, add = word(code, offset), word(code, offset + 4)
        if adrp & 0x9F000000 != 0x90000000 or add & 0xFFC00000 != 0x91000000:
            continue
        register = adrp & 31
        if add & 31 != register or (add >> 5) & 31 != register:
            continue
        immediate = ((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3)
        if immediate & (1 << 20):
            immediate -= 1 << 21
        address = ((code_va + offset) & ~0xFFF) + immediate * 0x1000
        address += (add >> 10) & 0xFFF
        if address == table_va:
            result.append(offset)
    return result


@dataclass(frozen=True)
class Site:
    name: str
    offset: int
    va: int
    before: bytes
    after: bytes
    segment: str
    bundle: str = PMU

    def state(self, data):
        current = data[self.offset:self.offset + len(self.before)]
        if current == self.before:
            return "before"
        if current == self.after:
            return "after"
        raise PatchError(f"{self.name}: neither exact before nor exact after")

    def report(self, data):
        return dict(name=self.name, bundle=self.bundle, segment=self.segment,
                    file_offset=hex(self.offset), va=hex(self.va),
                    before=self.before.hex(), after=self.after.hex(),
                    input_state=self.state(data), output_state="after")


class Plist:
    """Resolve prelink IDREFs, but edit only a personality's owning value token.

    No whole-plist reserialization and no mutation of a shared string definition.
    The full decoded dictionary is compared after editing, including KASLR data.
    """
    def __init__(self, xml):
        self.xml = xml
        try:
            self.root = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise PatchError(f"invalid prelink XML: {exc}") from exc
        elements = list(self.root.iter())
        ids = [e.attrib["ID"] for e in elements if "ID" in e.attrib]
        if len(ids) != len(set(ids)):
            raise PatchError("duplicate prelink ID")
        self.ids = {e.attrib["ID"]: e for e in elements if "ID" in e.attrib}
        self.refs = {e.attrib["IDREF"] for e in elements if "IDREF" in e.attrib}
        starts = list(re.finditer(rb'<(plist|dict|array|key|string|integer|data|true|false)(?=[\s>/])[^>]*>', xml))
        if len(starts) != len(elements) or any(m[1].decode() != e.tag for m, e in zip(starts, elements)):
            raise PatchError("prelink token mapping mismatch")
        self.starts = {e: m for e, m in zip(elements, starts)}
        self.info = self.decode(self.root)
        self.entries = self.dictionary(self.root[0] if self.root.tag == "plist" else self.root)["_PrelinkInfoDictionary"]
        if "IDREF" in self.entries.attrib:
            raise PatchError("shared prelink entry array")
        self.bundles = {}
        for e in self.entries:
            identifier = self.decode(self.dictionary(e)["CFBundleIdentifier"])
            if identifier in self.bundles:
                raise PatchError(f"duplicate bundle {identifier}")
            self.bundles[identifier] = e

    def resolve(self, element, seen=()):
        ref = element.attrib.get("IDREF")
        if ref is None:
            return element
        if ref in seen or ref not in self.ids:
            raise PatchError("cyclic or dangling prelink IDREF")
        return self.resolve(self.ids[ref], (*seen, ref))

    def dictionary(self, element):
        element = self.resolve(element)
        if element.tag != "dict" or len(element) % 2:
            raise PatchError("expected plist dictionary")
        result = {}
        for i in range(0, len(element), 2):
            if element[i].tag != "key" or element[i].text in result:
                raise PatchError("invalid or duplicate plist key")
            result[element[i].text] = element[i + 1]
        return result

    def decode(self, element, seen=()):
        ref = element.attrib.get("IDREF")
        if ref is not None:
            if ref in seen or ref not in self.ids:
                raise PatchError("cyclic or dangling prelink IDREF")
            return self.decode(self.ids[ref], (*seen, ref))
        if element.tag == "plist":
            return self.decode(element[0], seen)
        if element.tag == "dict":
            return {k: self.decode(v, seen) for k, v in self.dictionary(element).items()}
        if element.tag == "array":
            return [self.decode(e, seen) for e in element]
        if element.tag == "integer":
            value = element.text or "0"
            return int(value, 16 if value.lower().startswith("0x") else 10)
        if element.tag in ("string", "key"):
            return element.text or ""
        if element.tag in ("true", "false"):
            return element.tag == "true"
        if element.tag == "data":
            import base64
            return base64.b64decode(element.text or "")
        raise PatchError(f"unexpected plist type {element.tag}")

    def personality(self, bundle, name):
        try:
            entry = self.bundles[bundle]
            personalities = self.dictionary(entry)["IOKitPersonalities"]
            personality = self.dictionary(personalities)[name]
        except KeyError as exc:
            raise PatchError(f"missing personality {bundle}/{name}") from exc
        if any("IDREF" in e.attrib or e.attrib.get("ID") in self.refs
               for e in (entry, personalities, personality)):
            raise PatchError("shared personality dictionary; refusing")
        return self.dictionary(personality)

    def string_edit(self, element, value):
        if element.tag != "string" or element.attrib.get("ID") in self.refs:
            raise PatchError("cannot modify a shared string definition")
        token = self.starts[element]
        end = token.end()
        if not token[0].endswith(b"/>"):
            end = self.xml.index(b"</string>", end) + len(b"</string>")
        return token.start(), end, b"<string>" + value.encode("ascii") + b"</string>"


def plist_plan(xml):
    plist = Plist(xml)
    expected = deepcopy(plist.info)
    entries = {e["CFBundleIdentifier"]: e for e in expected["_PrelinkInfoDictionary"]}
    pmu = entries.get(PMU, {}).get("IOKitPersonalities", {})
    arm = entries.get(ARM_WDT, {}).get("IOKitPersonalities", {})
    if set(pmu) != {"PMU", "PMURTC", "PMUWatchDogTimer"} or set(arm) != {"AppleARMWatchdogTimer"}:
        raise PatchError("unexpected iOS 15 PMU/watchdog personality set")
    invariants = [(arm["AppleARMWatchdogTimer"], "IONameMatch", "wdt,s5l8960x"),  # must stay as is
                  (pmu["PMU"], "IOClass", "AppleD2207PMU"),
                  (pmu["PMU"], "IOProviderClass", "AppleARMIICDevice"),
                  (pmu["PMURTC"], "IOClass", "AppleD2207PMURTC"),
                  (pmu["PMURTC"], "IOProviderClass", "AppleD2207PMU"),
                  (pmu["PMUWatchDogTimer"], "IOClass", "AppleD2207PMUWatchDogTimer"),
                  (arm["AppleARMWatchdogTimer"], "IOClass", "AppleARMWatchdogTimer"),
                  (arm["AppleARMWatchdogTimer"], "IOProviderClass", "AppleARMIODevice")]
    for field, value in {"IOPlatformQuiesceAction": 80000, "IOPlatformWakeAction": 350,
                         "IOPlatformActiveAction": 80000, "IOPlatformSleepAction": 350,
                         "IOPlatformPanicAction": 1000}.items():
        invariants.append((arm["AppleARMWatchdogTimer"], field, value))
    if any(p.get(key) != value for p, key, value in invariants):
        raise PatchError("PMU/RTC/AppleARMWatchdogTimer invariants mismatch")
    edits, reports, states = [], [], []
    for bundle, name, key, before, after in PERSONALITIES:
        fields = plist.personality(bundle, name)
        if key not in fields:
            raise PatchError(f"missing personality field {bundle}/{name}/{key}")
        element = fields[key]
        current = plist.decode(element)
        if current not in (before, after):
            raise PatchError(f"{bundle}/{name}/{key}: unexpected value {current!r}")
        state = "before" if current == before else "after"
        states.append(state)
        start, end, replacement = plist.string_edit(element, after)
        if state == "before":
            edits.append((start, end, replacement))
        entries[bundle]["IOKitPersonalities"][name][key] = after
        reports.append(dict(bundle=bundle, personality=name, key=key,
                            before=before, after=after, input_state=state,
                            xml_offset=hex(start), before_token=xml[start:end].decode(),
                            after_token=replacement.decode(), output_state="after"))
    output = xml
    for start, end, replacement in sorted(edits, reverse=True):
        output = output[:start] + replacement + output[end:]
    if Plist(output).info != expected:
        raise PatchError("unrelated prelink semantics changed")
    return output, reports, states


def code_plan(text, text_va, text_offset, code, code_va, code_offset):
    sites = []

    def add(name, relative, before, after, table=False):
        sites.append(Site(name, (text_offset if table else code_offset) + relative,
                          (text_va if table else code_va) + relative,
                          before, after, "__TEXT" if table else "__TEXT_EXEC"))

    table = variants(text, hardware.D2207_LDO_TABLE, hardware.D2186_LDO_TABLE, "LDO table")
    add("ldo_table", table, hardware.D2207_LDO_TABLE, hardware.D2186_LDO_TABLE, True)
    xref = unique(table_xrefs(code, code_va, text_va + table), "LDO table ADRP/ADD xref")
    start = code.rfind(words(SETLDO_HEAD), 0, xref)
    if start < 0 or xref - start > 0x400:
        raise PatchError("iOS 15 _setLDO prologue not found")
    end = code.find(words((0xD65F03C0,)), xref)
    if end < 0 or end - start > 0x1000:
        raise PatchError("_setLDO return not found")
    end += 4
    function = code[start:end]
    rail = variants(function, words((RAIL[0],)), words((RAIL[1],)), "rail range") + start
    if (rail + 12 != xref or word(code, rail + 8) != 0x2A1703F9
            or code[xref + 8:xref + 16] != words((0x52800188, 0x9BA86AFB))):
        raise PatchError("iOS 15 rail/row-size/table-index context mismatch")
    target = branch_target(code, rail + 4)
    if not start <= target < end or word(code, target) != 0xAA1803E0:
        raise PatchError("rail b.hi does not reach the _setLDO error epilogue")
    add("rail_range", rail, words((RAIL[0],)), words((RAIL[1],)))
    mask = variants(function, words((*MASK[0], MASK_SHIFT)),
                    words((*MASK[1], MASK_SHIFT)), "capability mask") + start
    mask_branch = word(code, mask + 12)
    if mask_branch & 0xFFF8001F != 0x37000008:
        raise PatchError("mask not followed by tbnz w8,#0")
    mask_target = mask + 12 + (((mask_branch >> 5) & 0x3FFF) * 4)
    if not start <= mask_target < end or word(code, mask_target) != 0x79400368:
        raise PatchError("mask branch target is not the LDO voltage check")
    add("capability_mask", mask, words(MASK[0]), words(MASK[1]))
    registers = variants(function, words((0xAA1303E0, hardware.REG_OLD, 0x52800023, hardware.BLR_X8)),
                         words((0xAA1303E0, hardware.REG_NEW, 0x52800023, hardware.BLR_X8)),
                         "special register read/write", 2)
    for i, relative in enumerate(registers):
        add(f"special_register_{i + 1}", start + relative + 4,
            words((hardware.REG_OLD,)), words((hardware.REG_NEW,)))
    # Anchor on unchanged CMP/conditional branch, then validate the exact skip.
    boosts = [i for i in hits(function, words((hardware.BOOST_CMP,)))
              if i >= 4 and word(function, i + 4) & 0xFF00001F == 0x54000008]
    boost = start + unique(boosts, "5V boost cmp/b.hi") - 4
    generic = branch_target(code, boost + 8)
    generic_context = words((0xF9400268, 0xF942E908, 0x9100BFE2, 0xAA1303E0,
                             0xAA1503E1, 0x52800023, hardware.BLR_X8))
    if (not boost + 12 <= generic < end or code[generic:generic + len(generic_context)] != generic_context
            or code[boost + 12:boost + 24] != words((0x529FCFC9, 0x72A00F29, 0x9AD92529))):
        raise PatchError("5V boost/generic register-write context mismatch")
    skip = 0x14000000 | ((generic - boost) // 4)
    add("boost_skip", boost, words((BOOST_SUB,)), words((skip,)))
    mapper = variants(code, words(hardware.D2207_GPIO), words(hardware.D2186_GPIO_PAD), "GPIO mapper")
    add("gpio_mapper", mapper, words(hardware.D2207_GPIO), words(hardware.D2186_GPIO_PAD))
    gpio = variants(code, words(GPIO_BLOCK), words(GPIO_BLOCK_NEW), "iOS 15 GPIO levels/mode-2")
    add("gpio_value_mask", gpio, words((GPIO_BLOCK[0],)), words((GPIO_BLOCK_NEW[0],)))
    add("gpio_mode2", gpio + 10 * 4, words((hardware.GPIO_MODE2_OLD,)), words((hardware.GPIO_MODE2_NEW,)))
    # Event lengths are guards, not a 13-byte experiment. Five transfers plus
    # three debug dumps, scoped to PMU; fail rather than silently restore 13.
    transfers = hits(code, words((hardware.MOV_W1_70, hardware.MOV_W3_14, hardware.BLR_X8)))
    unique(transfers, "14-byte register-0x70 transfers", 5)
    for offset in transfers:
        if word(code, offset - 4) != 0xAA1303E0:
            raise PatchError("event transfer receiver is not the PMU")
        context = code[max(0, offset - 24):offset]
        if (len(hits(context, words((0xF9400268, 0xF942E508))))
                + len(hits(context, words((0xF9400268, 0xF942E908)))) != 1):
            raise PatchError("event transfer lacks a PMU register read/write vtable call")
    debug = hits(code, words((hardware.MOV_W2_14,)))
    unique(debug, "14-byte event debug dumps", 3)
    dump_targets = []
    for offset in debug:
        call = word(code, offset + 4)
        if (call & 0xFC000000 != 0x94000000
                or word(code, offset - 12) & 0x9F00001F != 0x90000000
                or word(code, offset - 8) & 0xFFC003FF != 0x91000000):
            raise PatchError("event debug dump context mismatch")
        immediate = call & 0x3FFFFFF
        if immediate & (1 << 25):
            immediate -= 1 << 26
        target = offset + 4 + immediate * 4
        if not 0 <= target < len(code):
            raise PatchError("event debug dump target outside PMU")
        dump_targets.append(target)
    if len(set(dump_targets)) != 1:
        raise PatchError("event debug dumps do not call one common PMU helper")
    event_sites = sorted([i + 4 for i in transfers] + debug)
    if hits(code, words((hardware.MOV_W1_70, hardware.MOV_W3_13, hardware.BLR_X8))):
        raise PatchError("13-byte event transfer present")
    return sites, dict(table_xref=hex(code_va + xref),
                       setldo_window=[hex(code_va + start), hex(code_va + end)],
                       rail_register="w23", table_index_register="x25", row_bytes=12,
                       boost_target=hex(code_va + generic), boost_instruction=hex(skip),
                       event_sites=[dict(file_offset=hex(code_offset + i), va=hex(code_va + i),
                                         before=hex(word(code, i)), after=hex(word(code, i))) for i in event_sites])


def uart_plan(code, code_va, code_offset):
    """Locate the UFCON selection block in AppleSamsungSerial __TEXT_EXEC.

    The whole block (patched words in either state, fixed context words, and a
    `mov wN, #0` wildcard at +28) must match exactly once; fail-closed otherwise.
    """
    def matches(index):
        def check(offset):
            if offset + UART_SPAN > len(code):
                return False
            for delta, before, after in UART_FIFO:
                if word(code, offset + delta) != (before, after)[index]:
                    return False
            if any(word(code, offset + d) != v for d, v in UART_CONTEXT.items()):
                return False
            return word(code, offset + 28) & 0xFFFFFFE0 == 0x52800000
        return [o for o in range(0, len(code) - UART_SPAN + 1, 4) if check(o)]

    start = unique(sorted(set(matches(0) + matches(1))), "AppleSamsungSerial UFCON block")
    sites = [Site(f"uart_fifo_{delta}", code_offset + start + delta, code_va + start + delta,
                  words((before,)), words((after,)), "__TEXT_EXEC", SERIAL)
             for delta, before, after in UART_FIFO]
    return sites, dict(uart_fifo=hex(code_va + start))


def serial_code(kernel):
    if SERIAL not in kernel.kexts:
        raise PatchError("AppleSamsungSerial kext absent")
    segments = [s for s in kernel.ksegments(SERIAL) if s["name"] == "__TEXT_EXEC"]
    return unique(segments, "AppleSamsungSerial __TEXT_EXEC segment")


def native_profile(native):
    """Cross-check shared hardware ground truth against the supplied N56 KC."""
    table = unique(hits(native.data, hardware.D2186_LDO_TABLE), "native D2186 LDO table")
    mapper = unique(hits(native.data, words(hardware.D2186_GPIO)), "native D2186 GPIO mapper")
    mask = unique(hits(native.data, words(hardware.GPIO_LEVELS_NEW)), "native D2186 GPIO levels")
    mode2 = mask + hardware.GPIO_MODE2_OFFSET
    if word(native.data, mode2) != hardware.GPIO_MODE2_NEW:
        raise PatchError("native D2186 mode-2 value mismatch")
    if native.kexts.get("com.apple.driver.AppleD2186PMU", {}).get("IOKitPersonalities", {}).get("PMU", {}).get("IONameMatch") != "pmu,d2186":
        raise PatchError("native PMU match mismatch")
    return dict(sha256=hashlib.sha256(native.data).hexdigest(), ldo_table_offset=hex(table),
                ldo_sha256=hashlib.sha256(hardware.D2186_LDO_TABLE).hexdigest(),
                gpio_mapper_offset=hex(mapper), gpio_value_mask_offset=hex(mask),
                gpio_mode2_offset=hex(mode2), retained_bits="0x05", mode2_bits="0x10",
                watchdog_bundles=[b for b in native.kexts if "Watch" in b])


def adapt(kernel, native=None):
    """Return (same-sized KC bytes, JSON-safe report); all checks precede writes."""
    if b"Darwin Kernel Version 21.6.0" not in kernel.data or b"RELEASE_ARM64_T7000" not in kernel.data:
        raise PatchError("expected J96 iOS 15 Darwin 21.6 / ARM64_T7000")
    if PMU not in kernel.kexts:
        raise PatchError("AppleD2207PMU kext absent")
    segments = {s["name"]: s for s in kernel.ksegments(PMU)}
    if not {"__TEXT", "__TEXT_EXEC"}.issubset(segments):
        raise PatchError("expected split iOS 15 PMU text/executable segments")
    text, code = segments["__TEXT"], segments["__TEXT_EXEC"]
    text_offset = kernel.offset(text["vm"], text["fs"])
    code_offset = kernel.offset(code["vm"], code["fs"])
    sites, anchors = code_plan(kernel.read(text["vm"], text["fs"]), text["vm"], text_offset,
                               kernel.read(code["vm"], code["fs"]), code["vm"], code_offset)
    serial = serial_code(kernel)
    serial_offset = kernel.offset(serial["vm"], serial["fs"])
    uart_sites, uart_anchor = uart_plan(kernel.read(serial["vm"], serial["fs"]), serial["vm"], serial_offset)
    sites += uart_sites
    anchors.update(uart_anchor)
    xml, personalities, states = plist_plan(kernel.xml)
    states += [s.state(kernel.data) for s in sites]
    if len(set(states)) != 1:
        raise PatchError("mixed before/after profile; partial patch refused")
    pi = next(s for s in kernel.segs if s["name"] == "__PRELINK_INFO")
    if len(xml) > pi["fs"]:
        raise PatchError("prelink XML exceeds reserved segment capacity")
    reference = native_profile(native) if native is not None else None
    output = bytearray(kernel.data)
    for site in sites:
        output[site.offset:site.offset + len(site.after)] = site.after
    output[pi["fo"]:pi["fo"] + pi["fs"]] = xml.ljust(pi["fs"], b"\0")
    # Independently re-locate all after patterns and branch targets.
    after_sites, after_anchors = code_plan(bytes(output[text_offset:text_offset + text["fs"]]), text["vm"], text_offset,
                                          bytes(output[code_offset:code_offset + code["fs"]]), code["vm"], code_offset)
    after_uart, after_uart_anchor = uart_plan(bytes(output[serial_offset:serial_offset + serial["fs"]]),
                                              serial["vm"], serial_offset)
    after_sites += after_uart
    after_anchors.update(after_uart_anchor)
    _, _, after_states = plist_plan(bytes(output[pi["fo"]:pi["fo"] + pi["fs"]]).rstrip(b"\0"))
    if (sites != after_sites or anchors != after_anchors or any(s.state(output) != "after" for s in after_sites)
            or set(after_states) != {"after"} or len(output) != len(kernel.data)):
        raise PatchError("strong after verification failed")
    # Every non-whitelisted byte, including other drivers and relocation data,
    # must be unchanged. This also catches any future accidental scope expansion.
    masked = bytearray(output)
    for site in sites:
        masked[site.offset:site.offset + len(site.before)] = kernel.data[site.offset:site.offset + len(site.before)]
    masked[pi["fo"]:pi["fo"] + pi["fs"]] = kernel.data[pi["fo"]:pi["fo"] + pi["fs"]]
    if bytes(masked) != kernel.data:
        raise PatchError("bytes outside PMU sites/prelink changed")
    return output, dict(profile="D2186", ios="15.8.8", build="19H422", rtc=True,
                        watchdog=False, event_bytes=14, arm_watchdog="untouched", uart_fifo=anchors["uart_fifo"],
                        input_state=states[0], size=len(output),
                        input_sha256=hashlib.sha256(kernel.data).hexdigest(),
                        output_sha256=hashlib.sha256(output).hexdigest(),
                        native_reference=reference, anchors=anchors,
                        sites=[s.report(kernel.data) for s in sites], personalities=personalities,
                        verification=dict(before=True, after=True, exact_branch_target=True,
                                          plist_semantics=True, unrelated_bytes_unchanged=True,
                                          size_unchanged=True, kaslr_data_unchanged=True),
                        prelink=dict(file_offset=hex(pi["fo"]), capacity=pi["fs"],
                                     before_xml_bytes=len(kernel.xml), after_xml_bytes=len(xml)))
