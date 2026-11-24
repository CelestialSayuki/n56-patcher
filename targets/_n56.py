"""N56 设备、引导器和工具配置。"""

DEVICE = {'model': 'n56ap',
 'product': 'iPhone7,1',
 'ecid': '',
 'udid': '',
 'pmu': 'd2186',
 'touch': 'multi-touch,n56',
 'codec': 'CS42L67',
 'charger': 'SN2400',
 'memory': {'base': 0x800000000, 'size': 0x40000000}}

# 每个工具列出 Darwin 与 Linux 候选：core.host.architecture_issue 会拒绝错误平台的
# 二进制，所以同一份清单在 macOS 和 Linux 上都能挑到可用的一项。
TOOLS = {'img4': 'tools/img4lib/img4',
 'devicetree-repack': 'tools/devicetree-parse/devicetree-repack',
 'iBoot64Patcher': ['tools/SSHRD_Script/Darwin/iBoot64Patcher',
                    'tools/SSHRD_Script/Linux/iBoot64Patcher'],
 'KPlooshFinder': ['tools/SSHRD_Script/Darwin/KPlooshFinder',
                   'tools/SSHRD_Script/Linux/KPlooshFinder'],
 'gaster': ['tools/SSHRD_Script/Darwin/gaster', 'tools/bin/gaster',
            'tools/dualra1n/binaries/Darwin/gaster',
            'tools/SSHRD_Script/Linux/gaster', 'tools/dualra1n/binaries/Linux/gaster'],
 'irecovery': ['tools/SSHRD_Script/Darwin/irecovery',
               'tools/SSHRD_Script/Linux/irecovery',
               'tools/dualra1n/binaries/Linux/irecovery'],
 'iproxy': ['tools/SSHRD_Script/Darwin/iproxy',
            'tools/SSHRD_Script/Linux/iproxy',
            'tools/dualra1n/binaries/Linux/iproxy'],
 'sshpass': ['tools/SSHRD_Script/Darwin/sshpass', 'tools/SSHRD_Script/Linux/sshpass'],
 'Kernel64Patcher': ['tools/dualra1n/binaries/Darwin/Kernel64Patcher',
                     'tools/dualra1n/binaries/Linux/Kernel64Patcher'],
 'kairos': ['tools/dualra1n/binaries/Darwin/kairos',
            'tools/dualra1n/binaries/Linux/kairos']}
