"""TrustCache：从 donor IPSW 提取 + 往 launchd 签名缓存加 daemon 后扩展 TC。

两件事（都是「可选提取 trustcache」的落点）：
  2. build_launchd_cache(): iOS13 launchd 只运行签名缓存 mrm.plist 里列出的 daemon，
     launchd_cache_loader 校验其分离签名并要求 cdhash 在 trust cache 中。
     往 mrm.plist 加 daemon → 重新 ad-hoc 签名 → 把新 cdhash 插进静态 TC（v1，22字节/条，按 cdhash 排序）。

移植自 boot_ios13.sh 的 IPSW 提取逻辑 + launchd_cache.py。
"""
import os
import plistlib
import re
import struct
import subprocess
import shutil

from . import log
from .tools import run


class TrustCache:
    def __init__(self, ctx):
        self.ctx = ctx

    def build_launchd_cache(self, daemon_dir, out_dir=None):
        """加 daemon 到 mrm.plist 并产出 {mrm.plist, mrm.plist.sig, trustcache.raw}。

        需要 donors['launchd_orig']（证据源里的 mrm.plist.orig）与 donors['trustcache']（原始静态 TC）。
        """
        out_dir = out_dir or self.ctx.wk("launchd_cache")
        os.makedirs(out_dir, exist_ok=True)
        orig_plist = self.ctx.donor("launchd_orig")
        img4 = self.ctx.tool("img4")

        plist = os.path.join(out_dir, "mrm.plist")
        sig = os.path.join(out_dir, "mrm.plist.sig")
        raw = os.path.join(out_dir, "trustcache.raw")

        # 1. 构建缓存
        cache = plistlib.load(open(orig_plist, "rb"))
        daemons = cache["LaunchDaemons"]
        for name in sorted(os.listdir(daemon_dir)):
            if not name.endswith(".plist"):
                continue
            key = "/System/Library/LaunchDaemons/" + name
            daemons[key] = plistlib.load(open(os.path.join(daemon_dir, name), "rb"))
            log.log(f"  + {key}")
        with open(plist, "wb") as f:
            plistlib.dump(cache, f, fmt=plistlib.FMT_BINARY)

        # 2. ad-hoc 分离签名（sha1+sha256，和原版一致）
        if os.path.exists(sig):
            os.remove(sig)
        run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha1,sha256",
             "--pagesize", "4096", "--detached", sig, plist])
        out = subprocess.run(["codesign", "-d", "-vvvv", "--detached", sig, plist],
                             capture_output=True, text=True).stderr
        m = re.search(r"CandidateCDHash sha256=([0-9a-f]{40})", out)
        if not m:
            log.die("无法从 codesign 输出读取 sha256 cdhash:\n" + out)
        cdhash = bytes.fromhex(m.group(1))
        log.log(f"  新缓存 cdhash(sha256): {cdhash.hex()}")

        # 3. 插入静态 TC
        stock = os.path.join(out_dir, "trustcache.stock.raw")
        run([img4, "-i", self.ctx.donor("trustcache"), "-o", stock])
        b = open(stock, "rb").read()
        ver, = struct.unpack_from("<I", b, 0)
        n, = struct.unpack_from("<I", b, 20)
        if ver != 1 or len(b) != 24 + n * 22:
            log.die(f"TC 布局异常(version {ver}, {n} 条, {len(b)} 字节)")
        ents = [b[24 + i * 22:24 + (i + 1) * 22] for i in range(n)]
        if any(e[:20] == cdhash for e in ents):
            log.log("  cdhash 已在 TC 中")
        else:
            ents.append(cdhash + bytes([2, 0]))   # hash type 2 = sha256(截断), flags 0
            ents.sort(key=lambda e: e[:20])
        open(raw, "wb").write(b[:20] + struct.pack("<I", len(ents)) + b"".join(ents))
        log.log(f"  TrustCache: {n} → {len(ents)} 条")
        return {"plist": plist, "sig": sig, "raw": raw}

    @staticmethod
    def _entries(data):
        version, = struct.unpack_from("<I", data, 0)
        count, = struct.unpack_from("<I", data, 20)
        if version != 1 or len(data) != 24 + count * 22:
            log.die("TrustCache v1 布局错误")
        return data[:20], {data[24 + i * 22:44 + i * 22]: data[24 + i * 22:46 + i * 22]
                           for i in range(count)}

    @staticmethod
    def _cdhash(path, detached=None):
        command = ["codesign", "-d", "-vvvv"]
        if detached:
            command += ["--detached", detached]
        command.append(path)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            log.die(f"无法读取 cdhash: {path}\n{result.stderr}")
        match = re.search(r"CandidateCDHash sha256=([0-9a-f]{40})", result.stderr)
        if match is None:
            log.die(f"codesign 未输出 sha256 cdhash: {path}")
        return bytes.fromhex(match.group(1))

    def _combined_cache_cdhash(self):
        from patches.rootfs.baseband import EDITS

        output = self.ctx.wk("dyld_shared_cache_arm64.combined")
        if not os.path.exists(output):
            source = os.path.join(self.ctx.mount_rootfs("j96"),
                                  "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64")
            result = subprocess.run(["cp", "-c", source, output], capture_output=True)
            if result.returncode:
                shutil.copyfile(source, output)
            with open(output, "r+b") as stream:
                for offset, before_hex, after_hex in EDITS:
                    before, after = bytes.fromhex(before_hex), bytes.fromhex(after_hex)
                    stream.seek(offset)
                    if stream.read(len(before)) != before:
                        log.die(f"离线基带补丁 before 不匹配: 0x{offset:x}")
                    stream.seek(offset)
                    stream.write(after)
                for offset, before_hex, after_hex in (
                    (104, "0100000000000000", "0000000000000000"),
                    (1705017567,
                     "eb9880e86f1527e1674347bda9933653d3ccfbf4f35b7afc58d9dc03b4c9f7d9",
                     "ee66a62a874080f3f2e11f4ee246662faae59cc3fda82a508fd8c64f3ba29d1b"),
                ):
                    before, after = bytes.fromhex(before_hex), bytes.fromhex(after_hex)
                    stream.seek(offset)
                    if stream.read(len(before)) != before:
                        log.die(f"离线 Health 补丁 before 不匹配: 0x{offset:x}")
                    stream.seek(offset)
                    stream.write(after)
        return self._cdhash(output)

    def build_full(self):
        from patches.impl.rootfs.mrm import build_mrm
        from patches.impl.rootfs.health_derive import derive_health
        from patches.impl.rootfs.installd_empty_containers import build_installd
        from patches.impl.rootfs.backupd_empty_snapshot import build_backupd
        from patches.impl.rootfs.health_derive import base_trustcache
        from patches.impl.rootfs.phone_ui import app_machos, settings_binaries

        base = base_trustcache(self.ctx)
        data = open(base, "rb").read()
        header, entries = self._entries(data)

        mrm = build_mrm(self.ctx)
        hashes = {
            self._cdhash(mrm["plist"], mrm["sig"]),
            bytes.fromhex("4c18c48ad1d24e694c5ab4b70a1c54040759fd1e"),
            bytes.fromhex("06716767d351ae0c876b7d57cf59069d895c3373"),
            self._combined_cache_cdhash(),
        }
        hashes.update(bytes.fromhex(value) for value in self.ctx.t.get("profile_cdhashes", ()))
        hashes.add(self._cdhash(build_installd(self.ctx)))
        hashes.add(self._cdhash(build_backupd(self.ctx)))
        if "checkra1n" in self.ctx.t.get("features", ()):
            from patches.impl.rootfs.checkra1n import prepare
            hashes.update(self._cdhash(path) for path in prepare(self.ctx)["machos"])
        libraries = derive_health(self.ctx)
        for root, _, files in os.walk(libraries):
            for name in files:
                hashes.add(self._cdhash(os.path.join(root, name)))
        for binary in app_machos(self.ctx.mount_rootfs("n66")):
            hashes.add(self._cdhash(str(binary)))
        n66 = self.ctx.mount_rootfs("n66")
        j96 = self.ctx.mount_rootfs("j96")
        for relative in settings_binaries(n66, j96):
            hashes.add(self._cdhash(os.path.join(n66, relative)))
        for digest in hashes:
            entries[digest] = digest + bytes([2, 0])
        raw = self.ctx.wk("trustcache.full.raw")
        ordered = b"".join(entries[key] for key in sorted(entries))
        with open(raw, "wb") as stream:
            stream.write(header + struct.pack("<I", len(entries)) + ordered)
        log.log(f"完整 TrustCache: {len(entries)} 条")
        return raw
