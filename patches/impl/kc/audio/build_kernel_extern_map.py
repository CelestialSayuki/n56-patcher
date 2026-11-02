#!/usr/bin/env python3
"""Record the audio driver's verified iOS 12 to iOS 13 kernel entries."""
import json
import struct

from kernel_externs import HERE, ROOT, SOURCE, TARGET, Kernel, disassemble, metaclasses


SYMBOL_MAP = {
    0xfffffff007671510: ('_memcpy', 'memcpy / memmove',
                       '唯一 PC 相对字段屏蔽匹配，前 41 条一致；调用现场为 dst、src、len。'),
    0xfffffff0076b4890: ('_clock_delay_until', 'clock_delay_until(deadline)',
                       '读 cntpct_el0 与 CPU 时钟偏移后比较 deadline，长等待走 assert_wait/thread_block，短等待走 wfe；13 的 thread->cpu_data 偏移为 0x490。'),
    0xfffffff0076b4c08: ('_clock_interval_to_deadline', 'clock_interval_to_deadline(interval,scale,out)',
                       '纳秒转换乘法常量与三参数一致，结果存入 [x2]；音频调用以 interval=50、scale=1000000 写入对象+0x258。'),
    0xfffffff007b2c1b8: ('_kernel_debug', 'kernel_debug(debugid,arg1,arg2,arg3,arg4,arg5)',
                       '12/13 入口均从 tpidr_el1 读取 thread id 放入 x5、x6=0，再进入相同五事件参数框架；13 thread id 偏移为 0x440。'),
    0xfffffff007bc8178: ('_snprintf', 'snprintf(buffer,size,format,...)',
                       '24 条主体保持相同栈变参、字符回调和结尾 NUL 写入；调用现场 buffer=sp+8、size=32、format=%s-intmic。'),
    0xfffffff007cb0ee0: ('__ZN15OSMetaClassBase9_ptmf2ptfEPKS_MS_FvvEm', 'OSMetaClassBase::_ptmf2ptf',
                       '唯一屏蔽匹配，完整 5 条指令一致；音频把直接回调地址放入 x1、x2=0，返回值传事件源工厂。'),
    0xfffffff007cb6534: ('__ZN7OSArray12withCapacityEj', 'OSArray::withCapacity(capacity)',
                       '12 metaclass 初始化名为 OSArray；两版分配 0x28，调用 initWithCapacity（12 +0xc8 / 13 +0xd0），失败 release、成功返回对象。'),
    0xfffffff007cb6630: ('__ZN7OSArray11withObjectsEPPK8OSObjectjj', 'OSArray::withObjects(objects,count,capacity)',
                       '与 withCapacity 共用 OSArray vtable；三参数转交 initWithObjects（12 +0xd0 / 13 +0xd8）；调用现场为单个对象、count=1、capacity=0。'),
    0xfffffff007cb920c: ('__ZN20OSCollectionIterator14withCollectionEPK12OSCollection', 'OSCollectionIterator::withCollection',
                       '12 metaclass 初始化名为 OSCollectionIterator；两版分配 0x28、用 collection 调 initWithCollection（12 +0x88 / 13 +0x90）。'),
    0xfffffff007cd9b1c: ('__ZN8OSNumber10withNumberEyj', 'OSNumber::withNumber(value,bits)',
                       '12 metaclass 初始化名为 OSNumber；两版分配 0x18、保留 value 与 bits，调用 init(value,bits)（12 +0x70 / 13 +0x78）；音频 bits=64。'),
    0xfffffff007cdbfc4: ('__Znam', 'operator new[](size_t)',
                       '28 条主体逐段对应，size=0 时统一分配 1 字节，kalloc 后记账并清零；源镜像前一组 0x7cdbf10/0x7cdbf84 是标量 new/delete。'),
    0xfffffff007cdc034: ('__ZdaPv', 'operator delete[](void*)',
                       '完整入口对应：空指针直接返回，读取分配大小、扣除同一计数器、尾跳释放；与 0x7cdbfc4 数组分配器配对。'),
    0xfffffff007ce343c: ('__ZN8OSSymbol11withCStringEPKc', 'OSSymbol::withCString',
                       '锁住符号表查找、创建 OSSymbol、复制字符串再插入表；12 调 0x7cdff94（分配 length+1 并 memcpy），13 调 OSString::initWithCString=0x75da12c。'),
    0xfffffff007cecc44: ('__os_log_internal', '_os_log_internal(dso,log,type,format,...)',
                       '调用现场均为 Mach header、os_log、type、format 与栈变参；13 包装把 log/type/format/va_list 转交 0x75e33d8，保留空串检查、0x500 过滤和日志默认对象判断。'),
    0xfffffff007cfc4b4: ('_IOSleep', 'IOSleep(milliseconds)',
                       '两版完整 3 条包装一致：w1=1000000 后尾跳 delay_for_interval；13 直接入口为 0x75f82e4，尾跳 0x70efbc8。'),
    0xfffffff007d1d688: ('__ZNK9IOService10isInactiveEv', 'IOService::isInactive',
                       '完整 8 条一致，唯一虚槽变化 12 +0x290 / 13 +0x298；返回 getState() & 1。'),
    0xfffffff007d33210: ('__ZN9IOService24registerInterestedDriverEPS_', 'IOService::registerInterestedDriver',
                       '两版检查 PM 字段 +0x68/+0x60/+0x38、锁 +0xd8、创建 capacity=4 的 OSSet 放入 +0x238、把 interested driver 加入集合。'),
    0xfffffff007d33474: ('__ZN9IOService26deRegisterInterestedDriverEPS_', 'IOService::deRegisterInterestedDriver',
                       '与注册函数相同 PM 结构与锁；从 +0x238 集合移除 driver，并遍历 +0x38 下的 powerInformee 列表。音频传对象+0x198 作 driver。'),
    0xfffffff007d336c8: ('__ZN9IOService22acknowledgePowerChangeEPS_', 'IOService::acknowledgePowerChange',
                       '唯一前 24 条屏蔽匹配；参数 driver 被 retain 后存入 PM 请求+0x68，请求类型 0x81，返回值保持 IOReturn。'),
    0xfffffff007d44cb0: ('__ZN10IOWorkLoop8workLoopEv', 'IOWorkLoop::workLoop',
                       '12 metaclass 初始化名为 IOWorkLoop；两版分配 0x48、调用 init（12 +0x60 / 13 +0x68），失败 release。'),
    0xfffffff007d4747c: ('__ZN22IOInterruptEventSource20interruptEventSourceEP8OSObjectPFvS1_PS_iEP9IOServicei', 'IOInterruptEventSource::interruptEventSource(owner,action,provider,index)',
                       '12 metaclass 初始化名为 IOInterruptEventSource；分配 0x68，四参数按原顺序调用 init（12 +0xd0 / 13 +0xd8）；音频 provider 与 index=0 对应。'),
    0xfffffff007d4e390: ('__ZN18IOTimerEventSource16timerEventSourceEP8OSObjectPFvS1_PS_E', 'IOTimerEventSource::timerEventSource(owner,action)',
                       '12 metaclass 初始化名为 IOTimerEventSource；分配 0x60，固定 options=1 并转交 owner/action 调 init（12 +0x138 / 13 +0x140）。'),
}

PLATFORM_MAP = {
    0xfffffff007e6caa0: (0xfffffff005fbe7ac, 'AppleARMPlatform::getFunction',
                       '完整 20 条屏蔽匹配；按 name 查对象并调用虚槽 +0x28。'),
    0xfffffff007e6f5e0: (0xfffffff005fc19c4, 'AppleARMIISDevice factory(service,provider)',
                       '两版分配 0xc0、调用 IOService::C2(meta)、写 AppleARMIISDevice vtable、调用 instanceConstructed；service/provider 保持两参数顺序，init 虚槽 12 +0x538 / 13 +0x540。'),
}

CLASS_EVIDENCE = {
    0xfffffff007cb6534: (0xfffffff008a5b698, 0xfffffff00749c388, '__ZTV7OSArray'),
    0xfffffff007cb6630: (0xfffffff008a5b698, 0xfffffff00749c388, '__ZTV7OSArray'),
    0xfffffff007cb920c: (0xfffffff008a5b710, 0xfffffff00749c810, '__ZTV20OSCollectionIterator'),
    0xfffffff007cd9b1c: (0xfffffff008a5b808, 0xfffffff00749d140, '__ZTV8OSNumber'),
    0xfffffff007d44cb0: (0xfffffff008a5c6d0, 0xfffffff0074a1198, '__ZTV10IOWorkLoop'),
    0xfffffff007d4747c: (0xfffffff008a5c720, 0xfffffff0074a14c8, '__ZTV22IOInterruptEventSource'),
    0xfffffff007d4e390: (0xfffffff008a5c810, 0xfffffff0074a1e30, '__ZTV18IOTimerEventSource'),
    0xfffffff007e6f5e0: (0xfffffff008a5e668, 0xfffffff0074d3b10, None),
}


def branch_target(kernel, call):
    word = struct.unpack('<I', kernel.read(call, 4))[0]
    assert word & 0x7c000000 == 0x14000000, hex(call)
    immediate = word & 0x03ffffff
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return call + immediate * 4


def main():
    source, target = Kernel(SOURCE), Kernel(TARGET)
    symbols = json.loads((HERE.parent / 'vibration/target-symbols.json').read_text())
    donor = json.loads((HERE / 'donor-code.json').read_text())
    classes = metaclasses(source, 0xfffffff007cb0d60)
    reverse = {}
    for name, address in symbols.items():
        reverse.setdefault(int(address, 16), []).append(name)
    confirmed = {}
    for entry in donor['external_branches']:
        if entry['provider'] not in ('kernel', 'com.apple.driver.AppleARMPlatform'):
            continue
        before = int(entry['target'], 16)
        if before in SYMBOL_MAP:
            symbol, identity, evidence = SYMBOL_MAP[before]
            after = int(symbols[symbol], 16)
        elif before in PLATFORM_MAP:
            after, identity, evidence = PLATFORM_MAP[before]
        else:
            previous = entry['existing_mapping']
            after, identity, evidence = int(previous['to'], 16), previous['id'], previous['how']
        for call in entry['call_sites']:
            assert branch_target(source, int(call, 16)) == before
        assert any(segment['vm'] <= after < segment['vm'] + segment['fs']
                   and 'EXEC' in segment['name'] for segment in target.segs)
        assert disassemble(target, after, 4)
        record = dict(id=identity, to=hex(after), provider=entry['provider'], how=evidence,
                      target_symbols=reverse.get(after, []), call_sites=entry['call_sites'])
        if before in CLASS_EVIDENCE:
            meta, vtable, target_vtable_symbol = CLASS_EVIDENCE[before]
            class_record = dict(source_meta=hex(meta), source_vtable=hex(vtable), **classes[meta])
            if target_vtable_symbol:
                class_record['target_vtable'] = hex(int(symbols[target_vtable_symbol], 16) + 16)
            else:
                class_record['target_meta'] = '0xfffffff0077f0530'
                class_record['target_vtable'] = '0xfffffff006dce530'
                class_record['target_initializer'] = '0xfffffff005fc313c'
            record['class_evidence'] = class_record
        confirmed[entry['target']] = record
    counts = {provider: sum(record['provider'] == provider for record in confirmed.values())
              for provider in ('kernel', 'com.apple.driver.AppleARMPlatform')}
    assert counts == {'kernel': 32, 'com.apple.driver.AppleARMPlatform': 2}
    assert confirmed['0xfffffff007cfc4b4']['to'] == '0xfffffff0075f82e4'
    report = dict(source=str(SOURCE), target=str(TARGET), counts=counts, confirmed=confirmed,
                  map={before: record['to'] for before, record in confirmed.items()}, unresolved=[],
                  iosleep=dict(source='0xfffffff007cfc4b4', target='0xfffffff0075f82e4',
                               scale=1000000, source_delay='0xfffffff0076b4a5c',
                               target_delay='0xfffffff0070efbc8'))
    (HERE / 'kernel-extern-map.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(counts=counts, unresolved=report['unresolved'], output=str(HERE / 'kernel-extern-map.json'))))


if __name__ == '__main__':
    main()
