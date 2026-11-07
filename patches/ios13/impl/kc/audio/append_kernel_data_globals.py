#!/usr/bin/env python3
"""Append the audio driver's data symbols and metaclass pointer slots."""
import json
import struct

from kernel_externs import HERE, ROOT, SOURCE, TARGET, Kernel, address_registers, disassemble, metaclasses, real


META_SLOTS = (0xfffffff00749c928, 0xfffffff00749d120, 0xfffffff00749dea8)
LOG_DEFAULT = 0xfffffff008a5b95c
STACK_GUARD = 0xfffffff008a12080


def main():
    source, target = Kernel(SOURCE), Kernel(TARGET)
    symbols = json.loads((HERE.parent / 'vibration/target-symbols.json').read_text())
    classes = metaclasses(source, 0xfffffff007cb0d60)
    references = json.loads((HERE / 'donor-references.json').read_text())['references']
    uses = {address: [hex(entry['pc']) for entry in references if entry['old'] == address]
            for address in (*META_SLOTS, LOG_DEFAULT, STACK_GUARD)}
    log_target = int(symbols['__os_log_default'], 16)
    create_target = int(symbols['_os_log_create'], 16)
    assert address_registers(source, disassemble(source, 0xfffffff007cecc30, 12))['x0'] == LOG_DEFAULT
    assert address_registers(target, disassemble(target, create_target, 12))['x0'] == log_target
    globals_map = {
        hex(LOG_DEFAULT): dict(id='_os_log_default', kind='address', to=hex(log_target),
                               target_symbol='__os_log_default', reference_pcs=uses[LOG_DEFAULT],
                               how='音频以此地址作为 _os_log_internal 的 log 参数。12 的 0x7cecc30 与 13 的 _os_log_create=0x75e3388 各用三指令返回默认日志对象地址。'),
        hex(STACK_GUARD): dict(id='__stack_chk_guard', kind='value_address',
                               to=symbols['___stack_chk_guard'], target_symbol='___stack_chk_guard',
                               reference_pcs=uses[STACK_GUARD],
                               how='音频从此地址读取 64 位 stack guard；13 导出 ___stack_chk_guard=0x76eb000。'),
    }
    for slot in META_SLOTS:
        source_meta = real(struct.unpack('<Q', source.read(slot, 8))[0])
        source_class = classes[source_meta]
        name = source_class['name']
        meta_symbol = f'__ZN{len(name)}{name}10gMetaClassE'
        pointer_symbol = f'__ZN{len(name)}{name}9metaClassE'
        target_meta = int(symbols[meta_symbol], 16)
        target_pointer_slot = int(symbols[pointer_symbol], 16)
        assert real(struct.unpack('<Q', target.read(target_pointer_slot, 8))[0]) == target_meta
        globals_map[hex(slot)] = dict(id=f'{name}::metaClass pointer', kind='metaclass_pointer_slot',
                                      source_pointee=hex(source_meta), target_pointee=hex(target_meta),
                                      target_gmeta_symbol=meta_symbol,
                                      target_existing_pointer_slot=hex(target_pointer_slot),
                                      reference_pcs=uses[slot],
                                      source_class_initializer=source_class['initializer'],
                                      how=f'旧 RO 槽指向 {name} 的 gMetaClass；名称由源 OSMetaClass 初始化实参确认，13 原生 metaClass 指针槽读回同一目标 gMetaClass。',
                                      resolution='在注入 RO 段写入 target_pointee，并把旧 LDR 槽地址映射到新槽。')
    path = HERE / 'kernel-extern-map.json'
    report = json.loads(path.read_text())
    report['data_globals'] = globals_map
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(data_globals=globals_map), ensure_ascii=False))


if __name__ == '__main__':
    main()
