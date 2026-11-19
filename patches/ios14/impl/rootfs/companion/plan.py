"""健康 / 手表配套要从 N66 18H17 补到 System14 的文件与 launchd 任务。

文件：N66 有、J96 没有、路径属于健康或手表配套的文件，加上下面列出的守护进程，以及电话、
钱包两个 iPhone 独有 App（shared PHONE_APPS）。手表 App
（Bridge.app）在 N66 上是首次开机时从 private/var/staged_system_apps 安装的可删除 App，这里
直接放进 /Applications。.lproj 只留中英文（缺的语言回落到英文），省出空间。

launchd：N66 launchd 缓存里这些守护进程的任务，以及 N66 独有、且部署后路径存在的框架登记
（SystemLibraryTreeState）、App 扩展、App 删除服务。
"""
import os
import re
from pathlib import Path

from patches.shared.impl.rootfs.companion.plan import phone_apps

SCOPE = re.compile(
    r"health|nano|bridge|companion|watch|pairing|brook|sleep|respiratory|hearing|measure|"
    r"stateful|sensorkit|activitysharing|telephonyrpc|uitrigger", re.I)
ROOTS = ("Applications", "System/Library", "usr/libexec", "usr/lib")
STAGED = "private/var/staged_system_apps/Bridge.app"
INSTALLED = "Applications/Bridge.app"
LANGUAGES = {"Base", "en", "English", "en_GB", "en_AU", "zh_CN", "zh-Hans", "zh_TW", "zh-Hant",
             "zh_HK", "zh-Hant-HK"}
# 不随配套部署：车载、Animoji/面容、语音信箱、紧急 SOS（依赖 A9 以后的硬件或与本补丁无关）。
EXCLUDE = re.compile(r"CarPlay|carkit|Avatar|facemetrics|VisualVoicemail|/SOS\.framework", re.I)

HEALTH_DAEMONS = ("com.apple.healthappd", "com.apple.sensorkitd", "com.apple.SensorKitALSHelper")
WATCH_DAEMONS = (
    "com.apple.nanoregistryd", "com.apple.nanoregistrylaunchd", "com.apple.nanobackupd",
    "com.apple.nanoprefsyncd", "com.apple.nanotimekitcompaniond", "com.apple.wcd",
    "com.apple.addressbooksyncd", "com.apple.appconduitd", "com.apple.brook.brookcompaniond",
    "com.apple.bulletindistributord", "com.apple.companionappd", "com.apple.companioncamerad",
    "com.apple.companionfindlocallyd", "com.apple.companionmessagesd", "com.apple.eventkitsyncd",
    "com.apple.magicswitchd.companion", "com.apple.nanoappregistryd", "com.apple.nanomapscd",
    "com.apple.nanomediaremotelinkagent", "com.apple.nanonewscd", "com.apple.nanophone.server",
    "com.apple.nanoweatherprefsd", "com.apple.pairedsyncd", "com.apple.pairedunlockd-phone",
    "com.apple.relevanced.ios", "com.apple.remotemediaservicesd", "com.apple.screenshotsyncd",
    "com.apple.security.otpaird", "com.apple.NPKCompanionAgent", "com.apple.nptocompaniond",
    "com.apple.subridged",
)
DAEMONS = HEALTH_DAEMONS + WATCH_DAEMONS


def _lproj_allowed(relative):
    for part in relative.split("/"):
        if part.endswith(".lproj") and part[:-6] not in LANGUAGES:
            return False
    return True


def _walk(root, start):
    base = root / start
    if not base.exists():
        return
    for directory, names, files in os.walk(base):
        names.sort()
        for name in sorted(files):
            yield os.path.relpath(os.path.join(directory, name), root)


def program(job):
    return job.get("Program") or job["ProgramArguments"][0]


def files(n66, j96, daemons):
    """返回 [(N66 相对路径, System14 相对路径)]。"""
    n66, j96 = Path(n66), Path(j96)
    chosen = {}
    for start in ROOTS:
        for relative in _walk(n66, start):
            if (SCOPE.search(relative) and not EXCLUDE.search(relative)
                    and _lproj_allowed(relative) and not os.path.lexists(j96 / relative)):
                chosen[relative] = relative
    for relative in _walk(n66, STAGED):
        if _lproj_allowed(relative):
            chosen[relative] = INSTALLED + relative[len(STAGED):]
    for relative in phone_apps(n66, j96):
        chosen[relative] = relative
    for job in daemons.values():
        relative = program(job).lstrip("/")
        if not os.path.lexists(j96 / relative):
            chosen[relative] = relative
    return sorted(chosen.items())


def _name(key):
    """缓存键是 plist 路径；按文件名选（有些任务的 Label 与文件名不同）。"""
    return key.rsplit("/", 1)[-1].removesuffix(".plist")


def launchd_jobs(n66_cache, j96_cache):
    """N66 launchd 缓存里选中的守护进程：{缓存键: 任务}。"""
    selected = {}
    for key, job in n66_cache["LaunchDaemons"].items():
        if _name(key) in DAEMONS and key not in j96_cache["LaunchDaemons"]:
            selected[key] = job
    missing = set(DAEMONS) - {_name(key) for key in selected}
    if missing:
        raise ValueError(f"N66 launchd 缓存里找不到：{sorted(missing)}")
    return selected


def merge_launchd(j96_cache, n66_cache, exists):
    """把配套任务与登记并进 J96 的缓存（就地修改并返回）。exists(path) 判断部署后路径是否存在。"""
    j96_cache["LaunchDaemons"].update(launchd_jobs(n66_cache, j96_cache))
    added = {}
    for section in ("SystemLibraryTreeState", "AppExtensions", "AppRemovalServices"):
        target = j96_cache.setdefault(section, {})
        count = 0
        for key, value in n66_cache.get(section, {}).items():
            if key in target or EXCLUDE.search(key):
                continue
            path = value.get("_executablePath", key) if isinstance(value, dict) else key
            if exists(path):
                target[key] = value
                count += 1
        added[section] = count
    return added
