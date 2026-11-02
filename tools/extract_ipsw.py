#!/usr/bin/env python3
"""从 ipsw/ 下的 IPSW 生成构建输入，输出到 ipsw/cache/derived/。

产物与此前的固件提取物逐字节一致。需要先运行 tools/setup.py。
"""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[1]
IMG4 = REPO / 'tools/img4lib/img4'
DT_PARSE = REPO / 'tools/devicetree-parse/devicetree-parse'
OUT = REPO / 'ipsw/cache/derived'
N56 = 'iPhone_5.5_12.5.8_16H88_Restore.ipsw'
N66 = 'iPhone_5.5_13.7_17H35_Restore.ipsw'
J96 = 'iPad_64bit_TouchID_13.7_17H35_Restore.ipsw'
N56_ROOTFS = '038-87140-057.dmg'
WIFI = 'usr/share/firmware/wifi/C-4345__s-B1'
WIFI_FILES = ('barbera.trx', 'barbera.clmb', 'barbera.txcb')
OUTPUTS = (
    'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed',
    'extracted/n56ap_ios12/DeviceTree.n56ap.jsonc',
    'extracted/n66ap_ios13/kernelcache.release.n66.decompressed',
    'extracted/n66ap_ios13/DeviceTree.n66ap.jsonc',
    'extracted/j96ap_ios13/kernelcache.release.ipad5',
    'extracted/j96ap_ios13/038-68261-036.dmg.trustcache',
    *(f'wifi/C-4345__s-B1/{name}' for name in WIFI_FILES),
)


def run(*cmd):
    subprocess.run([str(c) for c in cmd], check=True)


def extract_member(ipsw, member, work):
    path = work / Path(member).name
    with zipfile.ZipFile(ipsw) as archive, archive.open(member) as source, open(path, 'wb') as dest:
        shutil.copyfileobj(source, dest, 8 * 1024 * 1024)
    return path


def copy_member(ipsw, member, dest, work):
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(extract_member(ipsw, member, work), dest)


def make_kernel(ipsw, member, dest, work):
    src = extract_member(ipsw, member, work)
    dest.parent.mkdir(parents=True, exist_ok=True)
    run(IMG4, '-i', src, '-o', dest)


def make_devicetree(ipsw, member, dest, work):
    im4p = extract_member(ipsw, member, work)
    binary = work / (im4p.stem + '.bin')
    run(IMG4, '-i', im4p, '-o', binary)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, 'wb') as f:
        subprocess.run([str(DT_PARSE), str(binary)], stdout=f, check=True)


def copy_wifi(ipsw, dest, work):
    dmg = extract_member(ipsw, N56_ROOTFS, work)
    mountpoint = work / 'n56-rootfs'
    mountpoint.mkdir()
    run('hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mountpoint, dmg)
    try:
        dest.mkdir(parents=True, exist_ok=True)
        for name in WIFI_FILES:
            shutil.copyfile(mountpoint / WIFI / name, dest / name)
    finally:
        run('hdiutil', 'detach', mountpoint)


def decrypt_iboot(ipsw, gaster, patcher, out=OUT):
    """解密 iBSS/iBEC 并给 iBSS 打补丁。设备需处于 DFU（密钥由设备 AES 引擎解开）。"""
    dest = out / 'extracted/n56ap_ios12'
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        ibss = extract_member(ipsw, 'Firmware/dfu/iBSS.n56.RELEASE.im4p', work)
        ibec = extract_member(ipsw, 'Firmware/dfu/iBEC.n56.RELEASE.im4p', work)
        run(gaster, 'pwn')
        run(gaster, 'decrypt', ibss, work / 'iBSS.dec')
        run(gaster, 'decrypt', ibec, dest / 'iBEC.n56.dec')
        subprocess.run([str(patcher), str(work / 'iBSS.dec'), str(dest / 'iBSS.n56.patched')], check=False)
        if not (dest / 'iBSS.n56.patched').exists():
            raise SystemExit('iBoot64Patcher 未生成 iBSS')


def generate(n56, n66, j96, out=OUT):
    extracted = out / 'extracted'
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        make_kernel(n56, 'kernelcache.release.iphone7', extracted / 'n56ap_ios12/kernelcache.release.iphone7.decompressed', work)
        make_devicetree(n56, 'Firmware/all_flash/DeviceTree.n56ap.im4p', extracted / 'n56ap_ios12/DeviceTree.n56ap.jsonc', work)
        make_kernel(n66, 'kernelcache.release.n66', extracted / 'n66ap_ios13/kernelcache.release.n66.decompressed', work)
        make_devicetree(n66, 'Firmware/all_flash/DeviceTree.n66ap.im4p', extracted / 'n66ap_ios13/DeviceTree.n66ap.jsonc', work)
        copy_member(j96, 'kernelcache.release.ipad5', extracted / 'j96ap_ios13/kernelcache.release.ipad5', work)
        copy_member(j96, 'Firmware/038-68261-036.dmg.trustcache', extracted / 'j96ap_ios13/038-68261-036.dmg.trustcache', work)
        copy_wifi(n56, out / 'wifi/C-4345__s-B1', work)


def main():
    ipsw = REPO / 'ipsw'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--n56-ipsw', type=Path, default=ipsw / N56)
    parser.add_argument('--n66-ipsw', type=Path, default=ipsw / N66)
    parser.add_argument('--j96-ipsw', type=Path, default=ipsw / J96)
    parser.add_argument('--out', type=Path, default=OUT)
    args = parser.parse_args()
    generate(args.n56_ipsw, args.n66_ipsw, args.j96_ipsw, args.out)
    print('derived inputs ready:', args.out.resolve())


if __name__ == '__main__':
    main()
