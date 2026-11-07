"""N56 设备、引导器和工具配置。"""

DEVICE = {'model': 'n56ap',
 'product': 'iPhone7,1',
 'ecid': '',
 'udid': 'acf519ceb4a8a1434979cf9aaebef3899df5ccd0',
 'pmu': 'd2186',
 'touch': 'multi-touch,n56',
 'codec': 'CS42L67',
 'charger': 'SN2400',
 'memory': {'base': 0x800000000, 'size': 0x40000000}}

TOOLS = {'img4': 'tools/img4lib/img4',
 'devicetree-repack': 'tools/devicetree-parse/devicetree-repack',
 'iBoot64Patcher': 'tools/SSHRD_Script/Darwin/iBoot64Patcher',
 'KPlooshFinder': 'tools/SSHRD_Script/Darwin/KPlooshFinder',
 'gaster': ['tools/SSHRD_Script/Darwin/gaster', 'tools/bin/gaster'],
 'irecovery': 'tools/SSHRD_Script/Darwin/irecovery',
 'iproxy': 'tools/SSHRD_Script/Darwin/iproxy',
 'sshpass': 'tools/SSHRD_Script/Darwin/sshpass',
 'Kernel64Patcher': 'tools/dualra1n/binaries/Darwin/Kernel64Patcher',
 'kairos': 'tools/dualra1n/binaries/Darwin/kairos'}
