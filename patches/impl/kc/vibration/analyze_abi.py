#!/usr/bin/env python3
"""Extract the DRV2604 provider ABI and its iOS 13 virtual-call changes."""
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
from paths import ROOT, DERIVED, INPUT, OUTPUT
from macho import Kernel
from port import instructions

DONOR = DERIVED / 'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed'
BASELINE = INPUT
CODE_START = 0xfffffff0086ee8f0
CODE_END = 0xfffffff0086efc68
PWM_META13 = 0xfffffff0077f0ae8
PWM_CTOR13 = 0xfffffff005fd9e74
PWM_DTOR13 = 0xfffffff005fd9e94


def real(pointer):
    return (pointer & 0xffffffffff) | 0xfffffff000000000 if pointer else 0


def vtable(kernel, address, chained=False):
    slots = []
    for i in range(256):
        value = struct.unpack('<Q', kernel.read(address + i * 8, 8))[0]
        value = real(value) if chained else value
        if not any(s['vm'] <= value < s['vm'] + s['fs'] and 'EXEC' in s['name']
                   for s in kernel.segs):
            return slots
        slots.append(value)
    raise ValueError('vtable boundary not found')


def locate_vtable(kernel, metaclass):
    segment = next(s for s in kernel.ksegments('com.apple.driver.AppleARMPlatform')
                   if s['name'] == '__TEXT_EXEC')
    code = instructions(kernel.read(segment['vm'], segment['fs']), segment['vm'])
    getters = []
    for a, b, c in zip(code, code[1:], code[2:]):
        if (a.mnemonic == 'adrp' and a.op_str.startswith('x0,')
                and b.mnemonic == 'add' and b.op_str.startswith('x0, x0,')
                and c.mnemonic == 'ret'
                and (a.operands[1].imm & ((1 << 64) - 1)) + b.operands[2].imm == metaclass):
            getters.append(a.address)
    getter, = getters
    segment = next(s for s in kernel.segs if s['name'] == '__PLK_DATA_CONST')
    raw = kernel.read(segment['vm'], segment['fs'])
    needle = struct.pack('<Q', getter)
    at = raw.index(needle)
    assert raw.find(needle, at + 8) == -1
    address = segment['vm'] + at - 7 * 8
    assert kernel.read(address - 16, 16) == bytes(16)
    return address, getter


def virtual_loads(code):
    """Object vptr loads plus the two explicit super-table dispatches."""
    patches = []
    static = {0xfffffff0086ee998: 'AppleARMPWM::start',
              0xfffffff0086ef288: 'AppleARMPWM::setProperties'}
    for previous, current in zip(code, code[1:]):
        if current.mnemonic != 'ldr' or len(current.operands) != 2:
            continue
        memory = current.operands[1]
        if memory.type != 3 or current.reg_name(memory.mem.base) != 'x8':
            continue
        is_object = (previous.mnemonic == 'ldr' and previous.op_str.startswith('x8, [')
                     and previous.operands[1].type == 3
                     and previous.operands[1].mem.disp == 0)
        if not is_object and current.address not in static:
            continue
        old = memory.mem.disp
        if old < 0x60:
            continue
        receiver = static.get(current.address, 'OSObject-derived object')
        if current.address in (0xfffffff0086eee6c, 0xfffffff0086eefe8, 0xfffffff0086ef374):
            receiver = 'AppleARMIICDevice::I2C transaction'
        elif current.address == 0xfffffff0086ee9e0:
            receiver = 'AppleARMIICDevice::getProperty'
        elif old == 0x78:
            receiver = 'AppleARMFunction::callFunction'
        patches.append(dict(pc=current.address, old_offset=old, new_offset=old + 8,
                            receiver=receiver, instruction=current.mnemonic + ' ' + current.op_str))
    return patches


def analyze(input_path=BASELINE, output_dir=None):
    donor, target = Kernel(DONOR), Kernel(input_path)
    pwm_address, getter = locate_vtable(target, PWM_META13)
    pwm12 = vtable(donor, 0xfffffff0074dbee8, True)
    pwm13 = vtable(target, pwm_address)
    iic12 = vtable(donor, 0xfffffff0074d26d0, True)
    iic13 = vtable(target, 0xfffffff006dcd078)
    assert len(pwm12) == 181 and len(pwm13) == 182
    assert len(iic12) == 173 and len(iic13) == 174
    symbols = json.loads((HERE / 'target-symbols.json').read_text())
    assert pwm13[12] == int(symbols['__ZN9IOService8DispatchE5IORPC'], 16)
    assert iic13[12] == pwm13[12]
    assert iic13[13] == int(symbols['__ZN8OSObject4initEv'], 16)
    # The complete shared IOService prefix is identical across these two classes.
    for i in range(168):
        if i not in (0, 1, 7, 64, 81, 82, 86, 103, 117):
            assert iic13[i] == pwm13[i]
    drv12 = vtable(donor, 0xfffffff007628560, True)
    overrides = [dict(old_slot=i, new_slot=i + (i >= 12), method=hex(method))
                 for i, method in enumerate(drv12) if method != pwm12[i]]
    code = instructions(donor.read(CODE_START, CODE_END - CODE_START), CODE_START)
    patches = virtual_loads(code)
    report = dict(insertion_slot=12, insertion_method='OSMetaClassBase::Dispatch(IORPC)',
                  ios13_service_override='IOService::Dispatch(IORPC)',
                  pwm12_slots=len(pwm12), pwm13_slots=len(pwm13),
                  iic12_slots=len(iic12), iic13_slots=len(iic13),
                  pwm13_metaclass=hex(PWM_META13), pwm13_getMetaClass=hex(getter),
                  pwm13_vtable=hex(pwm_address), pwm13_ctor=hex(PWM_CTOR13),
                  pwm13_dtor=hex(PWM_DTOR13), overrides=overrides,
                  virtual_call_patches=patches,
                  provider_transaction=dict(old_slot=171, new_slot=172,
                                            old_offset='0x558', new_offset='0x560',
                                            old_target=hex(iic12[171]), new_target=hex(iic13[172])))
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / 'provider-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PWM:', len(pwm12), '->', len(pwm13), hex(pwm_address))
    print('IICDevice:', len(iic12), '->', len(iic13))
    print('Virtual-call changes:', len(patches), 'Overrides:', overrides)
    return report


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=BASELINE)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    analyze(args.input, args.out)
