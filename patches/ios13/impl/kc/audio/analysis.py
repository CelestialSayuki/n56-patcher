"""音频移植用到的分析结果：构建时从 iOS 12 donor 与本次输入内核现算。

一次构建创建一个 Analysis（donor 所在的 derived 目录、本次输入内核、输出目录），显式传给需要它的函数。
每份结果第一次取用时生成，写到输出目录备查，之后在同一个 Analysis 内复用，不重复计算。
取用方拿到的是 JSON 往返后的新副本，与过去提交进仓库的快照文件类型一致，可以放心修改。
donor-code.json 含人工确认的映射，仍随仓库提供，不在这里生成。
"""
import json
from pathlib import Path

from core.context import DERIVED_DIR
from patches.ios13.impl.kc.audio.inspect_port import MASK, Kernel, kernel_paths, port_audit

CODE_START = 0xfffffff0086efd38
# donor 中 CS42L67 及其共用 Mikey 总线代码的结束地址（与 donor-code.json 的 start+size 一致）。
DONOR_END = 0xfffffff0086f9718
FREE_SEGMENTS = ('__PLK_TEXT_EXEC', '__PRELINK_TEXT', '__PLK_DATA_CONST', '__PRELINK_DATA')


def target_symbols(target):
    return {name: hex(address) for name, address in Kernel(target).symbols().items()}


def donor_references(donor):
    """donor 代码里每条分支与地址引用；ADRP 按实际使用它的指令记录。"""
    from patches.shared.impl.kc.audio.image import native_tables
    from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator
    source = Kernel(donor)
    size = DONOR_END - CODE_START
    tables = [(entry['start'], entry['end']) for entry in native_tables()]
    scanner = Relocator(source, CODE_START, DONOR_END, [Piece(CODE_START, CODE_START, size, size)],
                        lambda address: address, tables)
    references = []
    for index, instruction in enumerate(scanner.instructions):
        mnemonic, operands = instruction.mnemonic, instruction.operands
        if mnemonic == 'adrp':
            for consumer in scanner.address_consumers(index, instruction):
                references.append(dict(kind='adrp/' + consumer['kind'], pc=consumer['instruction'].address,
                                       old=consumer['old'], new=consumer['old']))
        elif mnemonic == 'adr':
            target = operands[1].imm & MASK
            references.append(dict(kind='adr', pc=instruction.address, old=target, new=target))
        elif mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or mnemonic.startswith('b.'):
            target = operands[-1].imm & MASK
            references.append(dict(kind=mnemonic, pc=instruction.address, old=target, new=target))
    return dict(unchanged=True, reference_count=len(references), references=references)


def allocation_space(target):
    """输入内核各段中不属于任何 kext、且全为 0 的区间，按大小从大到小排列。"""
    kernel = Kernel(target)
    claims = kernel.claims()
    result = {}
    for name in FREE_SEGMENTS:
        host = next(s for s in kernel.segs if s['name'] == name)
        start, end = host['vm'], host['vm'] + host['fs']
        spans = sorted((max(start, a), min(end, b)) for a, b, _ in claims if a < end and start < b)
        regions, cursor = [], start
        for first, last in spans + [(end, end)]:
            if cursor < first and kernel.read(cursor, first - cursor) == bytes(first - cursor):
                regions.append((cursor, first - cursor))
            cursor = max(cursor, last)
        result[name] = [dict(start=hex(address), size=size)
                        for address, size in sorted(regions, key=lambda p: p[1], reverse=True)]
    return result


class Analysis:
    """一次构建的分析输入与已算结果。

    paths：'12' donor、'13' 本次输入内核、'n66_13' N66 内核（见 inspect_port.kernel_paths）。
    output：分析结果的落盘目录；为 None 时只在内存里复用，不写文件（开发脚本可不给）。
    """

    def __init__(self, derived, target, output=None):
        self.paths = kernel_paths(derived, target)
        self.output = Path(output) if output is not None else None
        self._texts = {}

    def _result(self, name, generate):
        if name not in self._texts:
            text = json.dumps(generate(), ensure_ascii=False, indent=2) + '\n'
            if self.output is not None:
                self.output.mkdir(parents=True, exist_ok=True)
                (self.output / name).write_text(text)
            self._texts[name] = text
        return json.loads(self._texts[name])

    def target_symbols(self):
        return self._result('target-symbols.json', lambda: target_symbols(self.paths['13']))

    def donor_references(self):
        return self._result('donor-references.json', lambda: donor_references(self.paths['12']))

    def allocation_space(self):
        return self._result('allocation-space.json', lambda: allocation_space(self.paths['13']))

    def port_audit(self):
        return self._result('port-audit.json', lambda: port_audit(self.paths))

    def family_abi(self):
        from patches.ios13.impl.kc.audio.audio_family_inspect import family_abi
        return self._result('audio-family-abi.json', lambda: family_abi(self.paths, self.port_audit()))

    def mikey_abi(self):
        from patches.ios13.impl.kc.audio.build_mikey_abi import mikey_abi
        return self._result('mikey-abi.json', lambda: mikey_abi(self.paths, self.port_audit()))

    def kernel_extern_map(self):
        from patches.ios13.impl.kc.audio.append_kernel_data_globals import data_globals
        from patches.ios13.impl.kc.audio.build_kernel_extern_map import extern_map

        def generate():
            symbols = self.target_symbols()
            report = extern_map(self.paths, symbols)
            report['data_globals'] = data_globals(self.paths, symbols,
                                                  self.donor_references()['references'])
            return report
        return self._result('kernel-extern-map.json', generate)


def add_arguments(parser):
    """开发脚本的公共参数：输入内核必须显式给出，derived 默认仓库内 ipsw/cache/derived。"""
    parser.add_argument('--input', type=Path, required=True, help='iOS 13 输入内核（raw）')
    parser.add_argument('--derived', type=Path, default=Path(DERIVED_DIR),
                        help='从 IPSW 生成的输入目录（含 12 donor 与 N66 内核），默认 ipsw/cache/derived')
    parser.add_argument('--out', type=Path, default=None, help='分析结果写入目录；不给则不落盘')


def from_arguments(args):
    return Analysis(args.derived, args.input.resolve(), args.out)
