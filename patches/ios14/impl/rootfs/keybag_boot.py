"""保留原生 keybag 启动配置与系统 TrustCache。"""
from pathlib import Path
import shutil
import struct

from core.trustcache import TrustCache


def original_launchd(ctx):
    source = Path(ctx.derived_root) / "j96/launchd"
    if not source.exists():
        source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(ctx.mount_rootfs("j96")) / "sbin/launchd", source)
    return str(source)


def build(ctx):
    from patches.ios14.impl.rootfs import baseband_product, launchd_cache, motion_platform
    from patches.ios14.impl.rootfs.bluetoothd import BLUETOOL_CDHASH, build_bluetoothd
    from patches.ios14.impl.rootfs.dyld_cache import CACHE, combined_cdhash

    # 同一进程里（all）前面的 rootfs 阶段收尾会卸载源镜像，但 prepare_* 缓存的是挂载点下的路径。
    # 挂载点是固定的，这里先挂回去，缓存的路径就仍然有效。
    ctx.mount_rootfs("n66")
    ctx.mount_rootfs("j96")
    stock = ctx.wk("trustcache.stock.raw")
    ctx.tools.img4_extract(ctx.donor("trustcache"), stock)
    header, entries = TrustCache._entries(Path(stock).read_bytes())
    hashes = set()
    if launchd_cache.selected(ctx, "rootfs.thermal_platform", "core"):
        from patches.ios14.impl.rootfs.thermal.build import prepare as prepare_thermal
        hashes.update(TrustCache._cdhash(path) for path in prepare_thermal(ctx).values())
    if launchd_cache.required(ctx):
        cache = launchd_cache.build(ctx)
        hashes.add(TrustCache._cdhash(cache["plist"], cache["sig"]))
    if launchd_cache.companion_selected(ctx):
        from patches.ios14.impl.rootfs.companion.package import prepare as prepare_companion
        hashes.update(TrustCache._cdhash(path) for path in prepare_companion(ctx)["machos"])
        # 不含配套的那版缓存也放进来：System14 换回它（rootfs.companion 留了备份）同一个启动包也能开机。
        fallback = launchd_cache.build(ctx, companion=False)
        hashes.add(TrustCache._cdhash(fallback["plist"], fallback["sig"]))
    if launchd_cache.checkra1n_selected(ctx):
        from patches.ios14.impl.rootfs.checkra1n import prepare as prepare_checkra1n
        hashes.update(TrustCache._cdhash(path) for path in prepare_checkra1n(ctx)["machos"])
    typed = {}
    if launchd_cache.selected(ctx, "rootfs.cydia", "checkra1n"):
        # boot94 起在设备上验证过：Cydia 底包与 Cydia 的二进制都放进启动 TrustCache，
        # 只有 sha1 签名的那些按 sha1 类型收录。
        from patches.shared.impl.rootfs.cydia import machos as cydia_machos
        for path in cydia_machos(ctx):
            digest, kind = TrustCache._cdhash_any(path)
            typed[digest] = kind
    if launchd_cache.fairplay_selected(ctx):
        hashes.add(TrustCache._cdhash(str(Path(ctx.mount_rootfs("n66")) / "usr/sbin/fairplayd.H2")))
    bluetooth_selected = ("bluetooth" in ctx.t.get("features", ()) or
                          "rootfs.bluetoothd" in ctx.t.get("patches", ()))
    if bluetooth_selected and "rootfs.bluetoothd" not in ctx.t.get("exclude", ()):
        hashes.add(TrustCache._cdhash(build_bluetoothd(ctx)))
        hashes.add(BLUETOOL_CDHASH)
    baseband_selected = ("baseband" in ctx.t.get("features", ()) or
                         "rootfs.baseband_product" in ctx.t.get("patches", ()))
    # dyld cache：各功能改不同的页，TrustCache 里放全部页哈希修改一起生效后的 cdhash。
    cache_path = Path(ctx.mount_rootfs("j96")) / CACHE
    cache_hashes = []
    if baseband_selected and "rootfs.baseband_product" not in ctx.t.get("exclude", ()):
        baseband_product.page_hash_edit(cache_path)
        cache_hashes.append((baseband_product.HASH_OFFSET, baseband_product.HASH_BEFORE,
                             baseband_product.HASH_AFTER))
    if launchd_cache.selected(ctx, "rootfs.motion_platform", "motion"):
        cache_hashes.extend(motion_platform.verify_cache_pages(cache_path))
        hashes.add(TrustCache._cdhash(motion_platform.build_locationd(ctx)))
    if cache_hashes:
        hashes.add(combined_cdhash(cache_path, cache_hashes))
    for digest, kind in typed.items():
        entries[digest] = digest + bytes((kind, 0))
    for digest in hashes:
        entries[digest] = digest + bytes((TrustCache.HASH_SHA256, 0))
    output = ctx.wk("trustcache.full.raw")
    Path(output).write_bytes(header + struct.pack("<I", len(entries))
                             + b"".join(entries[key] for key in sorted(entries)))
    return output
