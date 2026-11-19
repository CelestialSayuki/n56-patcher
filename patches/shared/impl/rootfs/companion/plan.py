"""Health/Watch companion scope shared by the independent iOS builds (from 14.8)."""
import functools
import os
import re


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
# J96（iPad）没有、名字又不在 SCOPE 里的 iPhone 独有 App；代码依赖都在 J96 cache 里，整包照搬。
PHONE_APPS = ("Applications/MobilePhone.app", "Applications/Passbook.app")

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
    return iter(_listing(str(root), start))


@functools.lru_cache(maxsize=None)
def _listing(root, start):
    """Sorted file list of a read-only source mount; walked once per process."""
    base = os.path.join(root, start)
    if not os.path.exists(base):
        return ()

    def walk(top):
        out = []
        for directory, names, files in os.walk(top):
            names.sort()
            for name in sorted(files):
                out.append(os.path.relpath(os.path.join(directory, name), root))
        return out

    # Same order as one os.walk(base); the subtrees are scanned concurrently (I/O bound DMG).
    _, names, files = next(os.walk(base))
    subdirs = [os.path.join(base, name) for name in sorted(names)
               if not os.path.islink(os.path.join(base, name))]
    out = [os.path.relpath(os.path.join(base, name), root) for name in sorted(files)]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(8) as pool:
        for part in pool.map(walk, subdirs):
            out += part
    return tuple(out)


def phone_apps(n66, j96):
    """PHONE_APPS 里 J96 没有的文件（N66 相对路径，原位部署）。"""
    for app in PHONE_APPS:
        for relative in _walk(n66, app):
            if (not EXCLUDE.search(relative) and _lproj_allowed(relative)
                    and not os.path.lexists(j96 / relative)):
                yield relative


def program(job):
    return job.get("Program") or job["ProgramArguments"][0]


def _name(key):
    """缓存键是 plist 路径；按文件名选（有些任务的 Label 与文件名不同）。"""
    return key.rsplit("/", 1)[-1].removesuffix(".plist")
