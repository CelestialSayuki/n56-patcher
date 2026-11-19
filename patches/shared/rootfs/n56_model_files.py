from core.overlay import SourceItem, SourceOverlay


PATHS = (
    "System/Library/LaunchDaemons/com.apple.jetsamproperties.N56.plist",
    "usr/share/firmware/multitouch/N56.mtprops",
    "Library/Audio/Tunings/N56",
    "System/Library/Frameworks/MediaToolbox.framework/N56",
    "System/Library/PrivateFrameworks/ACTFramework.framework/N56",
)


class RootfsN56ModelFiles(SourceOverlay):
    id = "rootfs.n56_model_files"
    feature = "core"
    scope = "device"
    checkpoint_version = 2
    note = "从本机 SystemA 补 N56 机型文件"
    items = tuple(SourceItem(source="device_s1:" + path, dest=path,
                             op="copy-if-missing", depends_on_signing=False)
                  for path in PATHS) + (
        SourceItem(source="device_s1:System/Library/ProductDocuments/RegulatoryImages",
                   dest="System/Library/ProductDocuments/RegulatoryImages",
                   op="copy", depends_on_signing=False),
        SourceItem(source="device_s1:System/Library/Watchdog/ThermalMonitor.bundle/N56AP.bundle/Info.plist",
                   dest="System/Library/ThermalMonitor/N56AP-Info.plist",
                   op="copy-if-missing", depends_on_signing=False,
                   mode=0o644, uid=0, gid=0, check={"plist": True}),
    )

    def apply(self, ctx, art=None):
        super().apply(ctx, art)
        from patches.shared.impl.rootfs.regulatory_model import reader

        session = ctx.ssh
        helper = self.mount + "/.n56-regulatory-model"
        session.deploy_path(reader(ctx), helper, uid=0, gid=0)
        session.sh(f'chmod 755 "{helper}"')
        try:
            model = session.sh(f'"{helper}"').decode().strip()
        finally:
            session.sh(f'rm -f "{helper}"')
        # SettingsFoundation uses DeviceVariant=A as its N56 fallback. Match
        # that lookup to the physical model's original certification image.
        variant = {"A1522": "A", "A1524": "B"}.get(model)
        if variant is None:
            raise ValueError("N56 regulatory model is unknown: " + model)
        if variant == "B":
            images = self.mount + "/System/Library/ProductDocuments/RegulatoryImages/"
            suffix = "_3only_@3x~iphone.png"
            session.sh(f'cp -p "{images}RegulatoryInfo-N56AP-B{suffix}" '
                       f'"{images}RegulatoryInfo-N56AP-A{suffix}"')
        ctx.patch_reports[self.id] = {"regulatory_model": model, "regulatory_image_variant": variant}
        session.sync()
