"""N56 相机配置放到 14.8 读取的位置。

13.7 从 MediaToolbox.framework/<机型>/ 读 AVCaptureSession.plist 与 CameraSetup.plist，
rootfs.n56_model_files 把 N56 的原厂文件补在那里。14.8 改由 CMCapture 按 MobileGestalt 的
DeviceName 读 CMCapture.framework/<机型>/，目录不存在就用 Default；Default 只有旧式预设、
没有 MultiStream 格式表，相机 App 报 unsupported session preset、加不上输入。
"""
from pathlib import Path

from core.overlay import SourceItem, SourceOverlay
from patches.ios14.impl.rootfs.camera_config import DEST, SOURCE, convert


class CameraConfig(SourceOverlay):
    id = "rootfs.camera_config"
    feature = "camera"
    note = "N56 相机配置（AVCaptureSession / CameraSetup）放进 CMCapture.framework/N56"
    items = (
        SourceItem(source="device_s1:" + SOURCE + "/CameraSetup.plist",
                   dest=DEST + "/CameraSetup.plist", op="copy",
                   depends_on_signing=False, mode=0o644, uid=0, gid=0,
                   check={"plist": True}),
        SourceItem(source="derive:session", dest=DEST + "/AVCaptureSession.plist",
                   op="copy", depends_on_signing=False, mode=0o644, uid=0, gid=0,
                   check={"plist": True}),
    )

    def derive(self, ctx, name, item):
        relative = SOURCE + "/AVCaptureSession.plist"
        if ctx.donor_dir:
            raw = (Path(ctx.donor_dir) / relative).read_bytes()
        else:
            session = ctx.ssh
            ctx.verify_device_system(session)
            session.mount(ctx.t["mounts"]["system12"], "/mnt1", ro=True)
            raw = session.sh(f'cat "/mnt1/{relative}"')
        output = Path(ctx.wk("camera-config")) / "AVCaptureSession.plist"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(convert(raw))
        return str(output)
