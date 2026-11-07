"""需要从设备 SystemA 快照下来的 donor 白名单（按版本分组，合并后即为快照范围）。

规则：
- 只放设备独有、无法从 ipsw 重新派生的路径；ipsw 派生的 donor 不在此列。
- 覆盖 System 卷之前必须按本文件的并集完整快照；快照不完整则拒绝覆盖。
- 目录条目包含其下所有文件。
- 新增版本时只追加该版本的条目，不删除旧条目。
"""

# 每个版本需要的设备端路径（相对 SystemA 根）。
WHITELIST = {
    "ios13": (
        # 版本确认：覆盖前必须能读到本机版本，用于校验快照来源
        "System/Library/CoreServices/SystemVersion.plist",
        # Wi-Fi B1 固件（b1_firmware）
        "usr/share/firmware/wifi/C-4345__s-B1",
        # 基带 Mav10 固件（baseband_compatibility）
        "usr/local/standalone/firmware/Baseband/Mav10",
        # 蓝牙工具（bluetooth_userland）
        "usr/sbin/BlueTool",
        # 触摸与机型文件（n56_model_files）
        "usr/share/firmware/multitouch/N56.mtprops",
        "System/Library/LaunchDaemons/com.apple.jetsamproperties.N56.plist",
        "System/Library/Frameworks/MediaToolbox.framework/N56",
        "System/Library/PrivateFrameworks/ACTFramework.framework/N56",
        "System/Library/ProductDocuments/RegulatoryImages",
        "System/Library/Watchdog/ThermalMonitor.bundle/N56AP.bundle/Info.plist",
        "Library/Audio/Tunings/N56",
        # 出厂校准数据（factorydata）
        "System/Library/Caches/com.apple.factorydata",
        # 以下不经过 overlay，直接从 /mnt1 读取
        # SEP 固件（ramdisk.SEP_FIRMWARE、finish 阶段 cp，加密 Data 与 systembag 依赖）
        "usr/standalone/firmware/sep-firmware.img4",
        # 蓝牙守护进程（bluetoothd 补丁的来源）
        "usr/sbin/bluetoothd",
    ),
    # ios14 等版本尚未提交，提交时在此追加条目。
}


def union():
    """所有版本的并集，去重并保持首次出现的顺序。"""
    seen = []
    for paths in WHITELIST.values():
        for path in paths:
            if path not in seen:
                seen.append(path)
    return tuple(seen)


def covers(path):
    """路径是否落在白名单的某个条目下（条目本身或其子路径）。"""
    return any(path == entry or path.startswith(entry + "/") for entry in union())
