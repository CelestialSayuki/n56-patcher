#!/usr/bin/env python3
"""Extract the native DRV2604 provider ABI against the selected kernel."""
import json
from pathlib import Path
import struct
import sys

from patches.shared.impl.paths import ROOT, DERIVED, INPUT, OUTPUT
from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import instructions

DONOR = DERIVED / 'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed'
BASELINE = INPUT
CODE_START = 0xfffffff0086ee8f0
CODE_END = 0xfffffff0086efc68


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


def analyze(input_path=BASELINE, output_dir=None, *, donor_path=DONOR,
            pwm_meta, pwm_ctor, pwm_dtor, iic_address, symbols_path):
    donor, target = Kernel(donor_path), Kernel(input_path)
    pwm_address, getter = locate_vtable(target, pwm_meta)
    pwm12 = vtable(donor, 0xfffffff0074dbee8, True)
    target_pwm = vtable(target, pwm_address)
    iic12 = vtable(donor, 0xfffffff0074d26d0, True)
    target_iic = vtable(target, iic_address)
    assert len(pwm12) == 181 and len(target_pwm) == 182
    assert len(iic12) == 173 and len(target_iic) == 174
    symbols_path = Path(symbols_path)
    symbols = json.loads(symbols_path.read_text())
    assert target_pwm[12] == int(symbols['__ZN9IOService8DispatchE5IORPC'], 16)
    assert target_iic[12] == target_pwm[12]
    assert target_iic[13] == int(symbols['__ZN8OSObject4initEv'], 16)
    # The complete shared IOService prefix is identical across these two classes.
    for i in range(168):
        if i not in (0, 1, 7, 64, 81, 82, 86, 103, 117):
            assert target_iic[i] == target_pwm[i]
    drv12 = vtable(donor, 0xfffffff007628560, True)
    overrides = [dict(old_slot=i, new_slot=i + (i >= 12), method=hex(method))
                 for i, method in enumerate(drv12) if method != pwm12[i]]
    code = instructions(donor.read(CODE_START, CODE_END - CODE_START), CODE_START)
    patches = virtual_loads(code)
    report = dict(insertion_slot=12, insertion_method='OSMetaClassBase::Dispatch(IORPC)',
                  target_service_override='IOService::Dispatch(IORPC)',
                  pwm12_slots=len(pwm12), target_pwm_slots=len(target_pwm),
                  iic12_slots=len(iic12), target_iic_slots=len(target_iic),
                  target_pwm_metaclass=hex(pwm_meta), target_pwm_getMetaClass=hex(getter),
                  target_pwm_vtable=hex(pwm_address), target_pwm_ctor=hex(pwm_ctor),
                  target_pwm_dtor=hex(pwm_dtor), overrides=overrides,
                  virtual_call_patches=patches,
                  provider_transaction=dict(old_slot=171, new_slot=172,
                                            old_offset='0x558', new_offset='0x560',
                                            old_target=hex(iic12[171]), new_target=hex(target_iic[172])))
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / 'provider-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PWM:', len(pwm12), '->', len(target_pwm), hex(pwm_address))
    print('IICDevice:', len(iic12), '->', len(target_iic))
    print('Virtual-call changes:', len(patches), 'Overrides:', overrides)
    return report

