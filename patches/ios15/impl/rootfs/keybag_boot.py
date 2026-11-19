"""Opt-in protected Data bootstrap, native12 BAG1 preservation, native15 boot.

This protected-Data leaf does no preparation/install work in none/default mode;
that does NOT remove the all-mode native15 MKB/systembag boot prerequisite. Main
owns that bootstrap also for unencrypted Data. Build/signing is offline;
initialize_data is the explicit protected-Data installation entry. No volume formatting/selection, fake BAG1, new
boot jobs, private bag dumps, TC editing, or host execution of device ARM code.
The shared systembag.build_helper (including host-header fallback) belongs to
main. This leaf prepares/guards the native MKB separately from that compiler.
"""
from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess

from core.context import REPO
from patches.shared.impl.rootfs import systembag

BUILD = "19H422"
JOB = "/System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist"
CACHE = "System/Library/xpc/launchd.plist"
KEYBAG = "/mnt7/keybags/systembag.kb"
KEYBAG_RECOVERY = KEYBAG + ".writing"
LOCK = "/mnt7/.n56-ios15-keybag-init.lock"
REMOTE = "/mnt6/.n56-bootstrap/sep-data"
MARKER = "/mnt7/.n56-ios15-data"
PROFILE = Path(__file__).parents[1] / "kc/sep_data-keybag-16H88.json"
HELPER_CONTRACT = b"N56_SYSTEMBAG_RECOVERY_GUARD_V2"


def encrypted(ctx):
    mode = ctx.t.get("data_protection", "none")
    if mode not in ("none", "encrypted"):
        raise ValueError(f"unknown Data protection mode: {mode!r}")
    return mode == "encrypted"


def native_boot_requirements(ctx):
    """Mode names govern volume protection, NOT native15 MKB boot requirements.

    No I/O/artifact generation. Static evidence from J96 19H422 keybagd: normal
    --init requires the saved bag even after a no-protection map returns 0. Only native diagnostics/ephemeral modes skip; they must not be forced to
    emulate unencrypted Data. Main retains its all-mode genuine MKB bootstrap.
    """
    protected = encrypted(ctx)
    return dict(native15_systembag_required=True, native15_sks_mkb_load_required=True,
                protected_data_leaf_enabled=protected, unencrypted_volume_can_skip_mkb=False,
                systembag_provisioning_owner="main/native12 MKB bootstrap for both volume modes",
                existing_data_missing_bag_must_not_be_rekeyed=True,
                normal_boot_assumptions=["not diagnostic mode", "hw.ephemeral_storage == 0"],
                evidence="J96 19H422 usr/libexec/keybagd static --init control flow")


def guard_systembag_creation(*, bag_present, marker_present, successful_journal, allow_create, recovery_present=False):
    """Pure all-mode guard reusable by main before its none-mode MKB bootstrap."""
    if bag_present:
        return
    if recovery_present:
        raise ValueError("systembag recovery file exists; native15 must recover it, refuse to create/rekey")
    if marker_present:
        raise ValueError("Data initialization marker exists but systembag is missing; refuse to rekey existing Data")
    if successful_journal:
        raise ValueError("successful Data initialization journal exists but systembag is missing; refuse to rekey existing Data")
    if not allow_create:
        raise ValueError("systembag absent; explicit first-creation authorization required")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _write_report(ctx, name, report):
    output = Path(ctx.wk("keybag/" + name))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def _macho(raw):
    """Inspect device Mach-O only; never execute it with a host tool wrapper."""
    if len(raw) < 32 or struct.unpack_from("<II", raw) != (0xfeedfacf, 0x0100000c):
        raise ValueError("keybag artifact must be a thin arm64 Mach-O (not a host/ELF binary)")
    subtype, kind, count, total = struct.unpack_from("<IIII", raw, 8)
    if subtype & 0xff == 2:
        raise ValueError("arm64e/PAC artifact cannot run on N56/A8")
    if 32 + total > len(raw):
        raise ValueError("truncated Mach-O load commands")
    cursor, commands, imports, ios = 32, [], [], []
    for _ in range(count):
        cmd, size = struct.unpack_from("<II", raw, cursor)
        if size < 8 or cursor + size > 32 + total:
            raise ValueError("invalid keybag artifact load command")
        piece = raw[cursor:cursor + size]
        commands.append((cmd, piece))
        if cmd in (0xc, 0x18, 0x80000018, 0x8000001f, 0x80000023):
            at, = struct.unpack_from("<I", piece, 8)
            imports.append(piece[at:].split(b"\0")[0].decode())
        if cmd == 0x25:
            ios.append(struct.unpack_from("<I", piece, 8)[0])
        elif cmd == 0x32:
            platform, minimum = struct.unpack_from("<II", piece, 8)
            if platform != 2:
                raise ValueError("keybag artifact is not built for the iOS device platform")
            ios.append(minimum)
        cursor += size
    if cursor != 32 + total or not ios or max(ios) > 0x0cffff:
        raise ValueError("keybag artifact requires newer than native12 iOS, or lacks device deployment target")
    return dict(kind=kind, commands=commands, imports=imports, min_ios=max(ios))


def framework_proof(raw, patched=False):
    """Prove native create/save + reuse-existing-BAG1/no-global-roll branches.

    The *entire* original __TEXT sections must match after undoing exactly the
    reviewed w4 change. Code signing may change headers/LINKEDIT, not native
    create/save logic. This is code evidence, not a fabricated hardware bag or
    a claim that a device roundtrip happened.
    """
    meta = _macho(raw)
    if meta["kind"] != 6:
        raise ValueError("native MobileKeyBag must be a device dylib")
    p = json.loads(PROFILE.read_text())
    if not patched and _sha(raw) != p["source_sha256"]:
        raise ValueError("native12 MKB source is not the exact readonly 16H88 framework")
    for region in p["immutable_data_regions"]:
        lo, size = region["offset"], region["size"]
        if _sha(raw[lo:lo + size]) != region["sha256"]:
            raise ValueError("native12 MKB data/bindings differ from genuine native source")
    command_hashes = [(cmd, _sha(blob)) for cmd, blob in meta["commands"]]
    for guard in p["load_command_guards"]:
        if (guard["cmd"], guard["sha256"]) not in command_hashes:
            raise ValueError("native12 MKB code mapping/exports/deployment load-command mismatch")
    for region in p["export_regions"]:
        lo, size = region["offset"], region["size"]
        if _sha(raw[lo:lo + size]) != region["sha256"]:
            raise ValueError("native12 MKB public export trie mismatch")
    normalized = bytearray(raw)
    point = p["preserve_patch"]
    at = point["offset"]
    expected = bytes.fromhex(point["after" if patched else "before"])
    if normalized[at:at + 4] != expected:
        raise ValueError("native12 MKB preserve-BAG1 arg5 instruction mismatch")
    normalized[at:at + 4] = bytes.fromhex(point["before"])
    for section in p["text_sections"]:
        lo, size = section["offset"], section["size"]
        if _sha(normalized[lo:lo + size]) != section["sha256"]:
            raise ValueError(f"native12 MKB code/constant mismatch: {section['name']}")
    for name, proof in p["proof"].items():
        lo, size = proof["offset"], proof["size"]
        if _sha(normalized[lo:lo + size]) != proof["sha256"]:
            raise ValueError(f"native12 MKB create/save proof mismatch: {name}")
    return dict(build=p["build"], preserve_bag1=patched, native_chain=p["native_chain"],
                proof_checked=list(p["proof"]), original_text_verified=True, preexisting_hardware_bag1_required=True,
                hardware_bag_fabricated=False, hardware_bag1_readback_verified=False,
                meaning="arg5=1 reuses existing ES material and skips ES roll; genuine AKS bag/file save remains")


def embedded_boot(raw):
    needle = b"<key>keybag</key>"
    for match in re.finditer(re.escape(needle), raw):
        start = raw.rfind(b"<?xml", 0, match.start())
        end = raw.find(b"</plist>", match.start())
        if start >= 0 and end >= 0:
            try:
                boot = plistlib.loads(raw[start:end + 8]).get("Boot", {})
            except (ValueError, plistlib.InvalidFileException):
                continue
            if "keybag" in boot:
                return boot
    raise ValueError("native15 launchd embedded Boot/keybag task not found")


def _boot_check(launcher, cache):
    boot = embedded_boot(launcher)
    keybag = boot["keybag"]
    if keybag.get("Program") != "/usr/libexec/keybagd" or keybag.get("ProgramArguments") != ["keybagd", "--init"]:
        raise ValueError("native15 launchd keybagd --init task mismatch")
    for name, program in (("data-protection", "/usr/libexec/init_data_protection"),
                          ("launchd_cache_loader", "/usr/libexec/launchd_cache_loader")):
        if boot.get(name, {}).get("Program") != program or boot[name].get("RequireSuccess") is not True:
            raise ValueError(f"native15 launchd boot prerequisite mismatch: {name}")
    for name, phase in (("mount-phase-1", "1"), ("mount-phase-2", "2")):
        task = boot.get(name, {})
        if task.get("ProgramArguments") != ["mount", "-P", phase] or task.get("RequireSuccess") is not True:
            raise ValueError(f"native15 mount boot phase mismatch: {name}")
    job = cache.get("LaunchDaemons", {}).get(JOB)
    if (not isinstance(job, dict) or job.get("Label") != "com.apple.mobile.keybagd" or
            job.get("ProgramArguments") != ["/usr/libexec/keybagd", "-t", "15"] or
            job.get("RunAtLoad") is not True):
        raise ValueError("native15 cached keybagd -t 15 service mismatch")
    return dict(embedded_tasks={name: boot[name] for name in
                ("mount-phase-1", "mount-phase-2", "keybag", "data-protection", "launchd_cache_loader")},
                native_job=JOB, program_arguments=job["ProgramArguments"], run_at_load=True,
                init_entry="keybagd --init (native launchd Boot task; not a new daemon job)")


def audit_native_boot(root):
    root = Path(root)
    version = plistlib.loads((root / "System/Library/CoreServices/SystemVersion.plist").read_bytes())
    if version.get("ProductBuildVersion") != BUILD:
        raise ValueError("keybag boot source must be native J96 19H422")
    report = _boot_check((root / "sbin/launchd").read_bytes(), plistlib.loads((root / CACHE).read_bytes()))
    files = ("sbin/launchd", "usr/libexec/keybagd", "usr/libexec/init_data_protection",
             "usr/libexec/launchd_cache_loader", CACHE, CACHE + ".sig")
    hashes = {name: _sha((root / name).read_bytes()) for name in files}
    report.update(build=BUILD, native_files=hashes, cache_changed=False, new_launchd_jobs=[],
                  runtime_validated=False, native_boot_plan_verified=True,
                  data_protection_init="native gigalocker/xART initializer; platform-skip or actual success must be observed",
                  note="--init loads an existing genuine systembag, not a replacement for native12 creation")
    return report


def audit_composed_cache(root, cache, signature=None):
    """Audit actual native tasks/programs, allowing unrelated composed changes.

    Never require the composed cache to equal the stock whole-file hash. Native
    launchd embedded Boot tasks and the complete cached keybag job stay intact.
    """
    root = Path(root)
    report = audit_native_boot(root)
    if not isinstance(cache, dict):
        cache = plistlib.loads(Path(cache).read_bytes())
    stock = plistlib.loads((root / CACHE).read_bytes())
    _boot_check((root / "sbin/launchd").read_bytes(), cache)
    if cache.get("LaunchDaemons", {}).get(JOB) != stock["LaunchDaemons"][JOB]:
        raise ValueError("composed launchd altered native keybag service content")
    for name in ("Boot",):
        if name in stock and cache.get(name) != stock[name]:
            raise ValueError("composed launchd altered native cached Boot tasks")
    report.update(cache_changed=cache != stock, composed_cache_verified=True,
                  stock_cache_hash_required=False,
                  new_launchd_jobs=sorted(set(cache.get("LaunchDaemons", {})) -
                                         set(stock["LaunchDaemons"])))
    if signature is not None:
        report["composed_signature_sha256"] = _sha(Path(signature).read_bytes())
    return report


class _ScopedArtifacts:
    def __init__(self, ctx):
        self.ctx = ctx

    def __getattr__(self, name):
        return getattr(self.ctx, name)

    def wk(self, name):
        return self.ctx.wk("keybag/" + name)


def _codesign(path, sign=False):
    if sign:
        subprocess.run(["codesign", "-s", "-", "-f", str(path)], check=True, capture_output=True)
    subprocess.run(["codesign", "--verify", "--strict", str(path)], check=True, capture_output=True)


def prepare_framework(ctx):
    """Independent of iPhoneOS SDK; strict none no-op, owned readonly mount."""
    if not encrypted(ctx):
        return None
    output = Path(ctx.wk("keybag/bootstrap/MobileKeyBag.preserve-BAG1"))
    if output.is_file():
        framework_proof(output.read_bytes(), patched=True)
        _codesign(output)
        return str(output)
    supplied = os.environ.get("N56_IOS15_MKB_NATIVE")
    native = Path(supplied) if supplied else Path(ctx.wk("keybag/native/MobileKeyBag"))
    if not native.is_file():
        work = Path(ctx.wk("keybag/native"))
        work.mkdir(parents=True, exist_ok=True)
        image, mount = work / "ramdisk12.dmg", work / "mount"
        mount.mkdir(exist_ok=True)
        subprocess.run([ctx.tool("img4"), "-i", str(Path(REPO) / ctx.t["ramdisk_dir"] / "ramdisk.img4"),
                        "-o", str(image)], check=True, capture_output=True)
        subprocess.run(["hdiutil", "attach", "-readonly", "-owners", "on", "-nobrowse", "-noverify",
                        "-mountpoint", str(mount), str(image)], check=True, capture_output=True)
        try:
            version = plistlib.loads((mount / "System/Library/CoreServices/SystemVersion.plist").read_bytes())
            if version.get("ProductBuildVersion") != "16H88":
                raise ValueError("systembag creation requires native12 16H88 ramdisk MKB")
            shutil.copy2(mount / systembag.FRAMEWORK.lstrip("/"), native)
        finally:
            subprocess.run(["hdiutil", "detach", str(mount)], check=True, capture_output=True)
    raw = native.read_bytes()
    framework_proof(raw)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(systembag.patch_framework(raw))
    _codesign(output, sign=True)
    proof = framework_proof(output.read_bytes(), patched=True)
    proof.update(path=str(output), signed=True, sha256=_sha(output.read_bytes()))
    _write_report(ctx, "framework.proof.json", proof)
    return str(output)


def validate_helper(path):
    path = Path(path)
    raw = path.read_bytes()
    meta = _macho(raw)
    if meta["min_ios"] > 0x0c0000 or meta["kind"] != 2 or set(meta["imports"]) != {"/usr/lib/libSystem.B.dylib"}:
        raise ValueError("create_systembag must be a device executable with only real libSystem imports")
    if HELPER_CONTRACT not in raw:
        raise ValueError("create_systembag predates recovery-file/secure-readback guard; rebuild signed native12 helper")
    for token in (b"MKBKeyBagCreateSystem", b"--create", b"systembag.kb", b"MobileKeyBag", b"result=%d"):
        if token not in raw:
            raise ValueError("create_systembag helper CLI/native API contract mismatch")
    _codesign(path)
    result = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(path)],
                            check=True, capture_output=True)
    blob = result.stdout + result.stderr
    start, end = blob.find(b"<?xml"), blob.find(b"</plist>")
    if start < 0 or end < start:
        raise ValueError("create_systembag lacks explicit signed device entitlements")
    entitlements = plistlib.loads(blob[start:end + 8])
    required = plistlib.loads((Path(REPO) / "tools/systembag/create_systembag.entitlements").read_bytes())
    if any(entitlements.get(name) is not True for name in required):
        raise ValueError("create_systembag signed device entitlements are incomplete")
    return dict(path=str(path), sha256=_sha(raw), arm64_device=True, min_ios="12.0",
                imports=meta["imports"], signed=True, required_entitlements=list(required),
                host_execution=False, helper_contract=2, recovery_file_guard=True)


def prepare(ctx):
    if not encrypted(ctx):
        return {}
    if getattr(ctx, 'completed_package', False):
        artifacts = ctx.patch_reports['rootfs.keybag_boot']['artifacts']
        validate_helper(artifacts['helper'])
        framework_proof(Path(artifacts['framework']).read_bytes(), patched=True)
        _codesign(artifacts['framework'])
        return artifacts
    # The framework/proof is prepared even if helper compilation is unavailable.
    # Main owns the narrow shared build_helper SDK/header fallback.
    framework = prepare_framework(ctx)
    supplied = os.environ.get("N56_IOS15_SYSTEMBAG_HELPER")
    output = Path(ctx.wk("keybag/bootstrap/create_systembag"))
    if supplied:
        candidate = Path(supplied)
    else:
        # 不再复用缓存：契约字符串只能证明"是新格式"，不能证明它由当前源码编出（之前复用旧二进制导致 umask 改动从未生效）。
        candidate = Path(systembag.build_helper(_ScopedArtifacts(ctx)))
    helper_report = validate_helper(candidate)
    output.parent.mkdir(parents=True, exist_ok=True)
    if candidate.resolve() != output.resolve():
        shutil.copy2(candidate, output)
        output.chmod(0o755)
    artifacts = dict(helper=str(output), framework=framework)
    ctx._ios15_sep_data_keybag_artifacts = artifacts
    _write_report(ctx, "artifacts.report.json", dict(enabled=True, artifact_ready=True,
        artifacts=artifacts, helper=helper_report, framework=framework_proof(Path(framework).read_bytes(), True),
        signing_inputs=dict(paths=list(artifacts.values()), cache_plans=[]), encrypted_ready=False))
    return artifacts


def prepare_artifacts(ctx):
    """Same helper/framework shape as the shared API; compilation stays in main."""
    return prepare(ctx)


def signing_inputs(ctx):
    if not encrypted(ctx):
        return {"paths": [], "cache_plans": []}
    artifacts = prepare(ctx)
    return {"paths": [artifacts["helper"], artifacts["framework"]], "cache_plans": []}


def original_launchd(ctx):
    if not encrypted(ctx):
        raise ValueError("native keybag boot restoration is encrypted-mode only")
    root = Path(ctx.mount_rootfs("j96"))
    audit_native_boot(root)
    output = Path(ctx.wk("keybag/launchd.native15"))
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "sbin/launchd", output)
    return str(output)


def build(ctx):
    if not encrypted(ctx):
        return dict(enabled=False, paths=[], cache_plans=[], native_boot_requirements=native_boot_requirements(ctx))
    from .launchd_cache import build as compose_launchd, selected_transforms
    if selected_transforms(ctx):
        launch = compose_launchd(ctx)
        boot = audit_composed_cache(ctx.mount_rootfs("j96"), launch["plist"], launch["sig"])
    else:
        boot = audit_native_boot(ctx.mount_rootfs("j96"))
    artifacts = prepare(ctx)
    boot.update(enabled=True, artifact_ready=True, artifacts=artifacts,
                native_boot_requirements=native_boot_requirements(ctx),
                signing_inputs=dict(paths=list(artifacts.values()), cache_plans=[]), preserve_bag1=True,
                runtime_plan=runtime_plan(ctx), encrypted_ready=False)
    return _write_report(ctx, "boot.report.json", boot)


def runtime_plan(ctx):
    if not encrypted(ctx):
        return dict(enabled=False, steps=[], native_boot_requirements=native_boot_requirements(ctx))
    bindings = ctx.t.get("mounts", {})
    return dict(enabled=True, selected_system=bindings.get("system_b"), selected_data=bindings.get("data_b"),
        never_formats_or_selects_volumes=True, steps=[
            "main: load native SEP and require successful ping BEFORE newfs_apfs -P",
            "verify N56 native12 ramdisk, exact selected APFS encrypted Data and non-native slices; SystemA readonly and other Data unmounted",
            "mount selected System at /mnt6 and Data at /mnt7 (protect first; encrypted-only fallback)",
            "verify deployed native15 launchd embedded --init/data-protection tasks and cached -t 15 service",
            "reject corrupt/symlink bags, foreign initialized Data and creation over existing userdata",
            "create only absent systembag with native MKBKeyBagCreateSystem and guarded preserve-BAG1 framework",
            "read back genuine native-created bag; native API result and secure file metadata must agree",
            "copy native15 private/var with keybags excluded; compare bag hash before/after; sync",
            "only then commit .n56-ios15-data and a volume-bound journal; retain failure lock for explicit recovery",
            "reboot into 15: observe native keybagd --init, init_data_protection success/platform skip, first unlock",
            "live media/file-key, SEP wake and existing DataA validation remain runtime tests"],
        generic_interface=dict(sks_endpoint=0x12, request_version=0, scrd_endpoint=10, scrd_request=1,
            required_data_operations=["load saved systembag", "map/set keybag for selected volume", "lock/unlock", "file/media v0"],
            conditional_xart=dict(node="IODeviceTree:/arm-io/sep/iop-sep-nub/xART", services=["arts", "artr"],
                                  required="SIK/gigalocker if native15 initializer finds supported xART; otherwise observe its native skip")),
        touchid_required=False, hardware_bag1_fabricated=False)


def _bindings(ctx):
    mounts = ctx.t.get("mounts", {})
    system, data = mounts.get("system_b"), mounts.get("data_b")
    if (not isinstance(system, int) or isinstance(system, bool) or not isinstance(data, int) or isinstance(data, bool)
            or not 3 <= system <= 100 or not 3 <= data <= 100 or system == data):
        raise ValueError("encrypted bootstrap needs explicit distinct non-native System/Data bindings (s3..s100)")
    return system, data


def before_protected_create(ctx):
    """Main's hook BEFORE formatting. Never formats or depends on selected slice."""
    if not encrypted(ctx):
        return dict(enabled=False)
    session = ctx.ssh
    session.verify_ramdisk()
    _protect_other_volumes(session.sh("/sbin/mount").decode())
    session.require_sep()
    output = session.sh('/usr/libexec/seputil --ping 2>&1; rc=$?; printf "\\nN56_SEP_PING_RC=%d\\n" "$rc"; test "$rc" -eq 0')
    if b"N56_SEP_PING_RC=0" not in output or b"ping failed" in output.lower():
        raise ValueError("native SEP ping did not positively succeed; protected creation must not start")
    return dict(enabled=True, native_sep_ping=True, before_newfs_required=True)


def _protect_other_volumes(mounts, other_encrypted=()):
    # Native system may be used read-only for SEP; native/other Data must not
    # be active while the native12 API switches the device's in-memory bag.
    for line in mounts.splitlines():
        if line.startswith("/dev/disk0s1s1 on ") and "read-only" not in line:
            raise ValueError("native SystemA is mounted writable; refuse protected initialization")
        for index in {2, *other_encrypted}:
            if line.startswith(f"/dev/disk0s1s{index} on "):
                raise ValueError("native/other encrypted Data is mounted; do not switch systembag with it active")


def _mount_line(mounts, point, device):
    lines = [line for line in mounts.splitlines() if f" on {point} " in line]
    if not lines:
        return None
    if len(lines) != 1 or not lines[0].startswith(device + " on ") or not re.search(r"\(apfs(?:,|\))", lines[0]):
        raise ValueError(f"{point} is not the explicitly selected APFS device")
    if "read-only" in lines[0]:
        raise ValueError(f"{point} is read-only; bootstrap must not write")
    return lines[0]


def _volume_facts(ctx):
    from core.apfs import Apfs, NAME_OFF
    system, data = _bindings(ctx)
    apfs = Apfs(ctx)
    volumes = {v[0]: v[2] for v in apfs.volumes()}
    if system not in volumes or data not in volumes:
        raise ValueError("selected bootstrap volumes do not exist")
    if apfs.enc_state(volumes[system]) != "UNENCRYPTED" or apfs.enc_state(volumes[data]) != "encrypted":
        raise ValueError("bootstrap requires unencrypted System and encrypted Data; no conversion/format fallback")
    names = ctx.t.get("volumes", {}).get("names", {})
    for kind, index in (("system", system), ("data", data)):
        actual = volumes[index][NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode()
        if not getattr(ctx, "slot", None) and names.get(kind) and actual != names[kind]:
            raise ValueError(f"selected {kind} name does not match its binding")
    # UUID at apfs_vol_uuid (0xf0); no UUID-derived/fabricated wrapping key.
    uuid = volumes[data][0xf0:0x100]
    if len(uuid) != 16 or not any(uuid):
        raise ValueError("selected encrypted Data lacks a valid APFS volume UUID")
    return dict(system=system, data=data, encrypted=True, data_uuid=uuid.hex(),
                other_encrypted_slices=[index for index, sb in volumes.items()
                                        if index != data and apfs.enc_state(sb) == "encrypted"])


def _mount_selected(ctx, facts):
    session = ctx.ssh
    _protect_other_volumes(session.sh("/sbin/mount").decode(), facts.get("other_encrypted_slices", ()))
    session.check_mountpoint(f"/dev/disk0s1s{facts['system']}", "/mnt6")
    session.check_mountpoint(f"/dev/disk0s1s{facts['data']}", "/mnt7")
    installation = getattr(ctx, "installation", None)
    if installation is not None:
        installation.mount(facts["system"], "/mnt6")
        installation.mount(facts["data"], "/mnt7", protected=True)
    else:
        session.mount_install_volume(facts["system"], "/mnt6")
        session.mount_install_volume(facts["data"], "/mnt7", protected=True)
    mounts = session.sh("/sbin/mount").decode()
    if not _mount_line(mounts, "/mnt6", f"/dev/disk0s1s{facts['system']}"):
        raise ValueError("System mount absent")
    line = _mount_line(mounts, "/mnt7", f"/dev/disk0s1s{facts['data']}")
    if not line:
        raise ValueError("protected Data mount absent")
    return dict(device=f"/dev/disk0s1s{facts['data']}", encrypted_superblock=True,
                mount_line=line, protect_option_requested=True, plain_fallback_cannot_change_encrypted_volume=True)


def _deployed_boot(session, expected):
    version = plistlib.loads(session.sh("cat /mnt6/System/Library/CoreServices/SystemVersion.plist"))
    if version.get("ProductBuildVersion") != BUILD:
        raise ValueError("deployed System is not native15 19H422")
    launcher = session.sh("cat /mnt6/sbin/launchd")
    cache = plistlib.loads(session.sh("cat /mnt6/" + CACHE))
    report = _boot_check(launcher, cache)
    session.sh("test -s /mnt6/usr/libexec/keybagd && test -s /mnt6/usr/libexec/init_data_protection && "
               "test -s /mnt6/usr/libexec/launchd_cache_loader && test -s /mnt6/" + CACHE + ".sig")
    for name in ("sbin/launchd", "usr/libexec/keybagd", "usr/libexec/init_data_protection", "usr/libexec/launchd_cache_loader"):
        raw = launcher if name == "sbin/launchd" else session.sh("cat /mnt6/" + name)
        if _sha(raw) != expected["native_files"][name]:
            raise ValueError(f"deployed {name} is not the guarded native15 executable")
    native_job = expected.get("native_keybag_job")
    if native_job is not None and cache.get("LaunchDaemons", {}).get(JOB) != native_job:
        raise ValueError("deployed composed cache changed native keybag job")
    # Audit the ACTUAL cache here, not a whole stock/final-cache hash. The
    # shared launchd deployment owner separately verifies its exact signed pair;
    # protected-Data validation can precede later resource overlays in Flow.
    report["deployed_cache_sha256"] = _sha(session.sh("cat /mnt6/" + CACHE))
    report["deployed_cache_signature_sha256"] = _sha(session.sh("cat /mnt6/" + CACHE + ".sig"))
    report["stock_cache_hash_required"] = False
    report.update(deployed_boot_tasks_verified=True, native_executables_verified=True,
                  jobs_enabled_by_native15=True, executed=False)
    return report


def _bag(session):
    output = session.sh(f'if [ -L /mnt7/keybags ] || [ -L {KEYBAG} ]; then echo symlink; '
        f'elif [ -e {KEYBAG} ]; then /usr/bin/stat -f "%u %g %Lp %z" {KEYBAG}; '
        'else echo absent; fi').decode().strip()
    if output == "absent":
        return None
    if output == "symlink":
        raise ValueError("systembag is a symlink; refuse to replace or follow it")
    try:
        uid, gid, mode, size = output.split()
        uid, gid, mode, size = int(uid), int(gid), int(mode, 8), int(size)
    except ValueError as exc:
        raise ValueError("systembag metadata query failed") from exc
    if uid != 0 or gid != 0 or mode & 0o077 or not 0 < size <= 16 * 1024 * 1024:
        raise ValueError("existing systembag is empty/unsafe; never delete/recreate it automatically")
    session.sh(f"test -f {KEYBAG}")
    raw = session.sh(f"cat {KEYBAG}")
    if len(raw) != size:
        raise ValueError("systembag readback size mismatch")
    # Only a hash leaves this routine/report. No hardware BAG1/keybag bytes are
    # serialized into host work files, and no placeholder is accepted as proof
    # of successful native AKS creation/unwrapping.
    return dict(bytes=size, sha256=_sha(raw), uid=uid, gid=gid, mode=oct(mode))


def _recovery_present(session):
    # -L also catches dangling links: neither may be discarded as absent.
    output = session.sh(f"if [ -e {KEYBAG_RECOVERY} ] || [ -L {KEYBAG_RECOVERY} ]; "
                        "then echo present; else echo absent; fi").strip()
    if output not in (b"present", b"absent"):
        raise ValueError("systembag recovery-file query failed; refuse creation")
    return output == b"present"


def _create_bag(session, artifacts):
    session.sh('set -e; test ! -L /mnt7/keybags; test ! -e ' + KEYBAG +
        '; test ! -L ' + KEYBAG + '; test ! -e ' + KEYBAG_RECOVERY +
        '; test ! -L ' + KEYBAG_RECOVERY + '; if [ -d /mnt7/mobile/Library ] || [ -d /mnt7/containers ] || [ -e ' + MARKER +
        ' ]; then echo "refusing to rekey existing userdata" >&2; exit 71; fi; '
        'mkdir -p /mnt7/keybags; /usr/sbin/chown 0:0 /mnt7/keybags; chmod 700 /mnt7/keybags; mkdir -p ' + REMOTE)
    session.deploy_path(artifacts["helper"], REMOTE + "/create_systembag")
    session.deploy_path(artifacts["framework"], REMOTE + "/MobileKeyBag.preserve-BAG1")
    session.sh(f"chmod 755 {REMOTE}/create_systembag {REMOTE}/MobileKeyBag.preserve-BAG1")
    for key, name in (("helper", "create_systembag"), ("framework", "MobileKeyBag.preserve-BAG1")):
        if _sha(session.sh(f"cat {REMOTE}/{name}")) != _sha(Path(artifacts[key]).read_bytes()):
            raise ValueError("staged helper/framework differs from guarded signing input; do not create")
    output = session.sh(f"{REMOTE}/create_systembag --create /mnt7 {REMOTE}/MobileKeyBag.preserve-BAG1",
                        timeout=180).decode(errors="replace")
    if "MKBKeyBagCreateSystem result=0 hex=0x00000000" not in output:
        raise ValueError("native systembag create/save did not positively succeed; do not retry/rekey")
    # 原生创建已经成功、内容已落盘：把权限收紧到 0600（只改元数据，内容不动），在守卫内完成，
    # 不留下"不安全但已创建"的状态让人去手工修。_bag 随后仍会核对 0600 与大小。
    session.sh(f"chmod 600 {KEYBAG}")
    bag = _bag(session)
    if bag is None:
        raise ValueError("native create returned success without a persisted systembag")
    session.sync()
    return bag


def initialize_data(ctx, artifacts=None, *, allow_create=False):
    """Explicit installation stage; no operation (even SSH access) in none mode.

    Does NOT execute 15 keybagd --init inside a native12 ramdisk. Its native15
    launchd does that on actual boot. Existing bag is never overwritten. Locks
    persist on failure so a partial native create is never silently repeated.
    """
    if not encrypted(ctx):
        return dict(enabled=False, steps_executed=[], native_boot_requirements=native_boot_requirements(ctx))
    _bindings(ctx)
    artifacts = artifacts or prepare(ctx)
    validate_helper(artifacts["helper"])
    framework_proof(Path(artifacts["framework"]).read_bytes(), patched=True)
    _codesign(artifacts["framework"])
    session = ctx.ssh
    before_protected_create(ctx)
    facts = _volume_facts(ctx)
    mounted = _mount_selected(ctx, facts)
    expected = audit_native_boot(ctx.mount_rootfs("j96"))
    native_cache = plistlib.loads((Path(ctx.mount_rootfs("j96")) / CACHE).read_bytes())
    expected["native_keybag_job"] = native_cache["LaunchDaemons"][JOB]
    boot = _deployed_boot(session, expected)
    bag = _bag(session)
    if bag is None and _recovery_present(session):
        guard_systembag_creation(bag_present=False, marker_present=False,
            successful_journal=False, allow_create=allow_create, recovery_present=True)
    session.sh(f"test ! -L {MARKER}")
    initialized = session.sh(f"test -f {MARKER} && echo yes || true").strip() == b"yes"
    if initialized and bag is None:
        guard_systembag_creation(bag_present=False, marker_present=True,
                                 successful_journal=False, allow_create=allow_create)
    if not initialized and getattr(ctx, "keep_data", False):
        raise ValueError("keep_data without an initialization marker must not create a new systembag")
    journal = session.sh("if [ -L /mnt7/.n56-ios15-keybag-init.json ]; then exit 72; "
                        "elif [ -f /mnt7/.n56-ios15-keybag-init.json ]; then cat /mnt7/.n56-ios15-keybag-init.json; fi")
    if journal.strip():
        prior = json.loads(journal)
        if (prior.get("volume", {}).get("data_uuid") != facts["data_uuid"]
                or prior.get("build") != BUILD or prior.get("data_initialization_complete") is not True):
            raise ValueError("Data initialization journal belongs to a different volume; explicit recovery required")
        if bag is None:
            guard_systembag_creation(bag_present=False, marker_present=False,
                                     successful_journal=True, allow_create=allow_create)
    guard_systembag_creation(bag_present=bag is not None, marker_present=initialized,
                             successful_journal=bool(journal.strip()), allow_create=allow_create)
    session.sh(f"umask 077; mkdir {LOCK}")  # fails closed; never auto-delete a failed creation lock
    report = dict(enabled=True, build=BUILD, volume=facts, mount=mounted, native_boot=boot,
                  artifact_ready=True, preserve_bag1=True, already_initialized=initialized,
                  created=False, copied_var=False, encrypted_ready=False)
    try:
        if bag is None:
            bag = _create_bag(session, artifacts)
            report["created"] = True
        before = bag["sha256"]
        if not initialized and not getattr(ctx, "keep_data", False):
            session.copy_tree("/mnt6/private/var", "/mnt7", exclude=("./keybags",))
            report["copied_var"] = True
        elif not initialized:
            raise ValueError("keep_data without initialization marker requires explicit recovery, not first initialization")
        after = _bag(session)
        if after is None or after["sha256"] != before:
            raise ValueError("var initialization changed the systembag; do not commit Data marker")
        session.sync()
        report.update(systembag_persisted=True, systembag=after, bag_preserved_during_var_copy=True,
            native_api_create_save_observed=report["created"], data_initialization_complete=True,
            native15_boot_observed=False, hardware_bag1_readback_verified=False,
            pending=["native15 --init/data-protection initializer outcome", "AKS attach/unlock/media/file/wake roundtrips",
                     "DataA/global BAG1 validation; no hardware readback performed by this leaf"])
        # Commit after successful sync/readback. The journal is volume-bound,
        # contains no bag bytes, and is not interpreted as live encrypted-ready.
        payload = json.dumps(report, sort_keys=True).encode() + b"\n"
        session.sh("umask 077; cat > /mnt7/.n56-ios15-keybag-init.json.tmp", data=payload)
        session.sh("mv /mnt7/.n56-ios15-keybag-init.json.tmp /mnt7/.n56-ios15-keybag-init.json; "
                   f"touch {MARKER}; rmdir {LOCK}; rm -rf {REMOTE}")
        session.sync()
        return _write_report(ctx, "runtime-init.report.json", report)
    except BaseException:
        report.update(status="failed-no-automatic-retry", failure_lock=LOCK,
                      recovery="inspect native API output/bag and volume identity; never delete bag/BAG1 or repeat creation blindly")
        _write_report(ctx, "runtime-init.failure.json", report)
        raise
