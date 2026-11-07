"""iOS 13 用户态覆盖层的 TrustCache 集合。"""
import os
import shutil
import struct
import subprocess
from core import log
from core.trustcache import TrustCache


class Ios13TrustCache(TrustCache):
    def _combined_cache_cdhash(self):
        from patches.ios13.rootfs.baseband import EDITS

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
        from patches.ios13.impl.rootfs.mrm import build_mrm
        from patches.ios13.impl.rootfs.health_derive import derive_health
        from patches.ios13.impl.rootfs.installd_empty_containers import build_installd
        from patches.ios13.impl.rootfs.backupd_empty_snapshot import build_backupd
        from patches.ios13.impl.rootfs.health_derive import base_trustcache
        from patches.ios13.impl.rootfs.phone_ui import app_machos, settings_binaries

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
            from patches.ios13.impl.rootfs.checkra1n import prepare
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


def build(ctx):
    return Ios13TrustCache(ctx).build_full()
