"""N56 相机用户态配置：原生能力表进入 iOS 15 CMCapture 机型目录。

已用 J96/N66 19H422 的实际资源目录和 CMCapture reader 核验；不用
MediaToolbox 的旧读取位置或默认预设兜底。N56 16H88 的命名 MultiStream
表原样保留并验证引用，仅给后置补 hasAutoFocus；前置与 CameraSetup 不变。
"""
from pathlib import Path

from core.overlay import SourceItem, SourceOverlay
from patches.ios15.impl.rootfs.camera_config import (
    DEST, FILENAMES, SOURCE, build, plan_avgestalt,
)
from patches.ios15.impl.rootfs.dyld_cache import apply_edits


class CameraConfig(SourceOverlay):
    id = "rootfs.camera_config"
    feature = "camera"
    checkpoint_version = "avgestalt-n56-v1"
    after = ("rootfs.n56_model_files",)
    note = "19H422 CMCapture/N56 原生 MultiStream 能力表（保留 A8/H6，不搬 A9/H8）"
    items = (
        SourceItem(source="derive:session", dest=DEST + "/AVCaptureSession.plist",
                   op="copy", depends_on_signing=False, mode=0o644, uid=0, gid=0,
                   check={"plist": True}),
        SourceItem(source="device_s1:" + SOURCE + "/CameraSetup.plist",
                   dest=DEST + "/CameraSetup.plist", op="copy",
                   depends_on_signing=False, mode=0o644, uid=0, gid=0,
                   check={"plist": True}),
    )

    def derive(self, ctx, name, item):
        if name != "session":
            raise ValueError(f"未知相机派生项: {name}")
        if ctx.donor_dir:
            ctx.verify_device_system(None)
            root = Path(ctx.donor_dir)
            raw = {n: (root / SOURCE / n).read_bytes() for n in FILENAMES}
            provenance = {"donor_dir": str(root), "model": "N56", "build": "16H88",
                          "source_paths": [SOURCE + "/" + n for n in FILENAMES]}
        else:
            session = ctx.ssh
            ctx.verify_device_system(session)
            session.mount(ctx.t["mounts"]["system12"], "/mnt1", ro=True)
            raw = {n: session.sh(f'cat "/mnt1/{SOURCE}/{n}"') for n in FILENAMES}
            provenance = {"source": "verified N56 SystemA", "model": "N56", "build": "16H88",
                          "source_paths": [SOURCE + "/" + n for n in FILENAMES]}
        output = Path(ctx.wk("camera-config"))
        report = build(raw[FILENAMES[0]], raw[FILENAMES[1]], output, provenance=provenance)
        ctx.patch_reports[self.id] = report
        return str(output / FILENAMES[0])

    def signing_inputs(self, ctx):
        return {"cache_plans": (plan_avgestalt(ctx.mount_rootfs("j96")),)}

    def apply(self, ctx, art=None):
        plan = plan_avgestalt(ctx.mount_rootfs("j96"))
        super().apply(ctx, art)
        result = apply_edits(ctx.ssh, self.mount, plan)
        ctx.ssh.sync()
        ctx.patch_reports[self.id].update(
            cache_plan=plan,
            cache_result=result,
            trustcache_entries=result["trustcache_entries"],
        )
