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

    def build_full(self):
        import importlib
        builder = importlib.import_module(self.ctx.t["trustcache_builder"])
        return builder.build(self.ctx)
