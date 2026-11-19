"""19H422 N56 运动分组：locationd、CoreLocation、CoreMotion 三份同样的改写。

N56 保持原生枚举 0x34、provider 0x1f 和 Oscar/M8。19H422 的分派表是 int32 相对偏移（202 项，
不是 14 的字节 switch）：
  - provider 表 N56 项从 0x10（不支持）改指向 J96/N66 共用的受支持分支；
  - capability 表 N56 项改指向一个 16 字节专用桩，桩直接给出 N56 能力掩码 0x028af40781 后跳回出口；
  - 桩借用的是一段冷门旧诊断块，它唯一的条件前驱改成 nop，落回原本的"返回 0"。
掩码 = 15 的 M8/Oscar 低位与分组位 + N56 原生 iPhone 能力字段（0x1457c0781）按 15 的布局平移
（原生 iPhone 位 20/21/22/26/30/32 → 15 的 21/22/23/27/31/33）；A9/AOP 才有的新位（14、28、52）不继承。
"""
import json
import os
import subprocess
from pathlib import Path

from .dyld_cache import plan_edits

PATCH_ID = 'rootfs.motion_platform'
LOCATIOND = 'usr/libexec/locationd'
PRESERVE_METADATA = '--preserve-metadata=identifier,entitlements,requirements,flags'

# locationd 文件偏移。
LOCATIOND_EDITS = (
    (0x36397C, bytes.fromhex('10000000'), bytes.fromhex('e4000000')),  # provider 表 N56 项
    (0x364298, bytes.fromhex('10000000'), bytes.fromhex('ac030000')),  # capability 表 N56 项 → 桩
    (0x363E44, bytes.fromhex('c0190035'), bytes.fromhex('1f2003d5')),  # 旧诊断块前驱 cbnz → nop
    (0x36417C, bytes.fromhex('f40300f9a079009000b02291247d00b0'),      # 桩：movz/movk 掩码; b 出口
     bytes.fromhex('20f080d2805eb1f24000c0f2e7ffff17')),
)
# dyld cache VA：CoreLocation、CoreMotion。
CACHE_EDITS = (
    (0x18737CC90, bytes.fromhex('10000000'), bytes.fromhex('e4000000')),
    (0x18737D598, bytes.fromhex('10000000'), bytes.fromhex('e0030000')),
    (0x18737D110, bytes.fromhex('601b0035'), bytes.fromhex('1f2003d5')),
    (0x18737D47C, bytes.fromhex('f40300f9e00100f000001c9144020090'),
     bytes.fromhex('28f080d2885eb1f24800c0f2daffff17')),
    (0x18CD828A4, bytes.fromhex('10000000'), bytes.fromhex('e4000000')),
    (0x18CD82D24, bytes.fromhex('10000000'), bytes.fromhex('e0030000')),
    (0x18CC52A78, bytes.fromhex('601b0035'), bytes.fromhex('1f2003d5')),
    (0x18CC52DE4, bytes.fromhex('f40300f9a013009000400a91c41300f0'),
     bytes.fromhex('28f080d2885eb1f24800c0f2daffff17')),
)


def patch_locationd(source):
    data = bytearray(source)
    for offset, before, after in LOCATIOND_EDITS:
        if data[offset:offset + len(before)] != before:
            raise ValueError(f'locationd before 不匹配: 0x{offset:x}')
        data[offset:offset + len(after)] = after
    return bytes(data)


def write_report(directory, report):
    path = Path(directory) / 'motion-plan.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    return str(path.resolve())


def prepare(ctx):
    cached = ctx.patch_reports.get(PATCH_ID)
    if cached:
        return cached
    directory = Path(ctx.wk('motion-platform')).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    root = Path(ctx.mount_rootfs('j96'))
    output = directory / 'locationd.n56'
    output.write_bytes(patch_locationd((root / LOCATIOND).read_bytes()))
    subprocess.run(['codesign', '-s', '-', '-f', PRESERVE_METADATA, str(output)],
                   check=True, capture_output=True)
    os.chmod(output, 0o755)
    backend = plan_edits(root, CACHE_EDITS, owner=PATCH_ID)
    report = dict(patch_id=PATCH_ID, output=dict(path=str(output)), backend_plan=backend,
                  trustcache_entries=backend['trustcache_entries'])
    report['manifest'] = write_report(directory, report)
    ctx.patch_reports[PATCH_ID] = report
    return report


def build_locationd(ctx):
    return prepare(ctx)['output']['path']


def signing_inputs(ctx):
    report = prepare(ctx)
    return dict(paths=[report['output']['path']], cache_plans=[report['backend_plan']])
