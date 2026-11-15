"""设备 SystemA 的 donor 快照。

覆盖 System 卷之前，把 patches/shared/donor_whitelist.py 中所有条目完整拷到本地
state/donors/<设备ID>/，并写入 manifest.json（路径、大小、sha256）。之后所有
device_s1 来源都从快照读取，不再依赖设备上的原 SystemA。
"""
import hashlib
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import tempfile
import time

from patches.shared.donor_whitelist import union

from . import log

MANIFEST = "manifest.json"
PARTIAL_SUFFIX = ".partial"


class DonorError(RuntimeError):
    pass


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_files(root, entry):
    """条目对应的全部 (相对路径, 绝对路径)；目录展开为其下所有非目录项。"""
    base = os.path.join(root, entry)
    if os.path.isdir(base) and not os.path.islink(base):
        for dirpath, dirnames, filenames in os.walk(base):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                yield os.path.relpath(full, root), full
    else:
        yield entry, base


def build_manifest(tree, device_id, build, entries):
    """为已经放在 tree 中的白名单内容生成 manifest 字典（不写盘）。"""
    files, links = [], []
    for entry in entries:
        for rel, full in _entry_files(tree, entry):
            if os.path.islink(full):
                links.append({"path": rel, "target": os.readlink(full)})
            elif os.path.isfile(full):
                files.append({"path": rel, "size": os.path.getsize(full), "sha256": _sha256(full)})
    return {
        "device_id": device_id,
        "build": build,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "whitelist": list(entries),
        "files": files,
        "links": links,
    }


def missing_entries(tree, entries):
    return [e for e in entries if not os.path.lexists(os.path.join(tree, e))]


def finalize(tree, dest, device_id, build, entries=None):
    """把 tree 变成正式快照：写 manifest，然后原子地移到 dest。

    tree 中必须已经包含全部白名单条目；缺一个就报错，不产生半成品快照。
    """
    entries = tuple(union() if entries is None else entries)
    missing = missing_entries(tree, entries)
    if missing:
        raise DonorError("来源缺少白名单条目（快照未生成）: " + ", ".join(missing))
    if os.path.exists(dest):
        raise DonorError(f"快照已存在，不覆盖: {dest}")
    manifest = build_manifest(tree, device_id, build, entries)
    with open(os.path.join(tree, MANIFEST), "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    os.replace(tree, dest)
    return manifest


def snapshot_tree(source, dest, device_id, build, entries=None):
    """从一个已挂载或已解开的本地目录（如 IPSW 的 rootfs）生成快照。"""
    entries = tuple(union() if entries is None else entries)
    missing = missing_entries(source, entries)
    if missing:
        raise DonorError("来源缺少白名单条目（快照未生成）: " + ", ".join(missing))
    partial = dest + PARTIAL_SUFFIX
    shutil.rmtree(partial, ignore_errors=True)
    os.makedirs(partial)
    for entry in entries:
        src = os.path.join(source, entry)
        dst = os.path.join(partial, entry)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.isdir(src) and not os.path.islink(src):
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst, follow_symlinks=False)
    return finalize(partial, dest, device_id, build, entries)


def snapshot_device(session, system_slice, dest, device_id, expected_build, entries=None):
    """从设备 SystemA（s1，只读挂载在 /mnt1）通过 ssh 流式拷出白名单，生成快照。

    真机路径，需要 ramdisk 会话。快照生成后校验 SystemVersion 的 build。
    """
    entries = tuple(union() if entries is None else entries)
    session.mount(system_slice, "/mnt1", ro=True)
    staging = tempfile.mkdtemp(prefix="n56-donor-")
    try:
        names = " ".join(shlex.quote(e) for e in entries)
        producer = subprocess.Popen(
            session.ssh_argv() + [f"/usr/bin/tar -cpf - -C /mnt1 {names}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        consumer = subprocess.Popen(["/usr/bin/tar", "-xpf", "-", "-C", staging],
                                    stdin=producer.stdout, stderr=subprocess.PIPE)
        producer.stdout.close()
        _, err = consumer.communicate()
        producer.wait()
        if producer.returncode != 0 or consumer.returncode != 0:
            raise DonorError("白名单流式拷贝失败: " + (err or b"").decode(errors="replace")[:800])
        version_path = os.path.join(staging, "System/Library/CoreServices/SystemVersion.plist")
        with open(version_path, "rb") as stream:
            build = plistlib.load(stream).get("ProductBuildVersion", "")
        if build != expected_build:
            raise DonorError(f"设备 SystemA 为 build {build}，期望 {expected_build}，不生成快照")
        return finalize(staging, dest, device_id, build, entries)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        session.umount("/mnt1")


def verify(dest, entries=None):
    """检查快照是否可用。返回问题列表，空列表表示通过。

    检查项：manifest 存在；白名单条目全部被快照覆盖；每个文件存在且 sha256 一致。
    """
    problems = []
    path = os.path.join(dest, MANIFEST)
    if not os.path.isfile(path):
        return [f"缺少 {MANIFEST}: {dest}"]
    with open(path, encoding="utf-8") as stream:
        manifest = json.load(stream)
    required = tuple(union() if entries is None else entries)
    recorded = set(manifest.get("whitelist", []))
    for entry in required:
        if entry not in recorded:
            problems.append(f"快照未包含白名单条目: {entry}")
    for item in manifest.get("files", []):
        full = os.path.join(dest, item["path"])
        if not os.path.isfile(full):
            problems.append(f"文件缺失: {item['path']}")
        elif _sha256(full) != item["sha256"]:
            problems.append(f"sha256 不匹配: {item['path']}")
    return problems


def load_manifest(dest):
    with open(os.path.join(dest, MANIFEST), encoding="utf-8") as stream:
        return json.load(stream)


def donor_path(dest, rel):
    """快照中某个相对路径的本地位置（供 overlay 与补丁读取）。"""
    return os.path.join(dest, rel)


def snapshot_dir(state_dir, device_id):
    return os.path.join(state_dir, "donors", device_id)


def require_ready(dest):
    """覆盖 System 卷前的门禁：快照存在且通过校验，否则抛出 DonorError。"""
    problems = verify(dest)
    if problems:
        raise DonorError("donor 快照不可用，拒绝覆盖 System 卷：\n  " + "\n  ".join(problems[:8]))
    return load_manifest(dest)


__all__ = [
    "DonorError", "build_manifest", "finalize", "snapshot_tree", "snapshot_device",
    "verify", "load_manifest", "donor_path", "snapshot_dir", "require_ready", "missing_entries",
]


# 每次刷机都会按设备重新个性化签名的文件。快照若来自上一次刷机，这些文件就是旧的：
# 旧的 SEP 固件让 seputil --load 直接内核崩溃（实机），旧的基带票据让基带起不来。
PERSONALIZED = (
    "usr/standalone/firmware/sep-firmware.img4",
    "usr/local/standalone/firmware/Baseband/Mav10/bbticket.der",
    "usr/local/standalone/firmware/Baseband/Mav10/sbl1.mbn",
)


def refresh_if_stale(session, system_slice, dest, device_id, expected_build):
    """设备上的 iOS 12 还在时，比对个性化文件；与快照不一致说明快照来自上一次刷机，重新生成。
    iOS 12 已删（s1 读不到这些文件）时沿用现有快照。返回 True 表示快照已更新。"""
    session.mount(system_slice, "/mnt1", ro=True)
    try:
        stale = []
        for rel in PERSONALIZED:
            data = session.sh(f'cat "/mnt1/{rel}" 2>/dev/null', check=False)
            if not data:
                return False
            local = os.path.join(dest, rel)
            if not os.path.isfile(local):
                stale.append(rel)
                continue
            with open(local, "rb") as stream:
                if hashlib.sha256(stream.read()).digest() != hashlib.sha256(data).digest():
                    stale.append(rel)
    finally:
        session.umount("/mnt1")
    if not stale:
        return False
    log.warn("donor 快照来自上一次刷机（" + "、".join(os.path.basename(r) for r in stale) + " 与设备不同），重新生成")
    aside = dest + ".stale-" + time.strftime("%Y%m%d-%H%M%S")
    os.replace(dest, aside)
    try:
        snapshot_device(session, system_slice, dest, device_id, expected_build)
    except BaseException:
        if not os.path.exists(dest):
            os.replace(aside, dest)
        raise
    log.log(f"donor 快照已更新（旧快照留在 {aside}）")
    return True
