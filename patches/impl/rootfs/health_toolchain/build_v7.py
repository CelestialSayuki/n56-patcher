#!/usr/bin/env python3
"""repair-v7：在 repair-v6(分支修复)基础上，叠加 Swift _StringObject 等带标志绝对指针的重定位。

rebuild/compact 已加入对高位带标志(bit63)指针的低 56 位平移 + rebase 登记。
重跑完整链 rebuild→compact→selector→branch，输出 repair-v7(保留 v3/v4/v6)。
"""
import time

import prepare_runtime_repair as s1
import prepare_compact_repair as s2
import prepare_selector_repair as s3
import prepare_branch_repair as s4

FULL = s1.FULL
s1.OUT = FULL / 'repair-v7-rebuild'
s2.BASE = FULL / 'repair-v7-rebuild'; s2.OUT = FULL / 'repair-v7-compact'
s3.BASE = FULL / 'repair-v7-compact'; s3.OUT = FULL / 'repair-v7-selector'
s4.V3 = FULL / 'repair-v7-compact'           # 全 50 库回退来源
s4.V4 = FULL / 'repair-v7-selector'          # 选择子修复覆盖的 21 库
s4.OUT = FULL / 'repair-v7'

for name, stage in (('rebuild+swiftptr', s1), ('compact+swiftptr', s2),
                    ('selector', s3), ('branch', s4)):
    t = time.time()
    print(f'>>> {name} 开始', flush=True)
    stage.main()
    print(f'>>> {name} 完成 {time.time()-t:.0f}s', flush=True)
print('>>> repair-v7 完成', flush=True)
