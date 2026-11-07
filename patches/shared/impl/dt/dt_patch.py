#!/usr/bin/env python3
"""Build an N56 DeviceTree from its native tree and the target donor nodes."""

import argparse
import copy
import json
import os
import re
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patches.shared.impl.paths import DERIVED, OUTPUT

BASE = os.path.dirname(os.path.abspath(__file__))
EXTRACTED = str(DERIVED / "extracted")
N56_JSONC = os.path.join(EXTRACTED, "n56ap_ios12", "DeviceTree.n56ap.jsonc")
N66_JSONC = os.path.join(EXTRACTED, "n66ap_ios13", "DeviceTree.n66ap.jsonc")
OUT_JSONC = str(OUTPUT / "DeviceTree.n56_native.jsonc")
OUT_BIN = str(OUTPUT / "DeviceTree.n56_native.bin")

# ---- role configuration (must match on-disk APFS volume roles) -------------
# Stock iOS 13 values; s4/s5 superblocks are patched to match (see docstring).
SYSTEM_VOL_ROLE = 1
DATA_VOL_ROLE = 64

# Nodes ported wholesale from the N66AP iOS 13 donor.
PORTED_TOP_NODES = ["filesystems", "osenvironments"]


def load_jsonc(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        content = f.read()
    content = re.sub(r",(\s*[}\]])", r"\1", content)
    return json.loads(content)


def node_name(node_list: list) -> str:
    for item in node_list:
        if isinstance(item, dict) and item.get("name") == "name":
            return item.get("value", "")
    return ""


def find_node_by_path(items: list, parts: list):
    if not parts:
        return items
    target = parts[0]
    for item in items:
        if isinstance(item, list) and node_name(item) == target:
            return find_node_by_path(item, parts[1:])
    return None


def find_top_node(items: list, name: str):
    for item in items:
        if isinstance(item, list) and node_name(item) == name:
            return item
    return None


def add_prop(node_list: list, name: str, val, length: int = 4, disp: int = 1):
    for item in node_list:
        if isinstance(item, dict) and item.get("name") == name:
            item["value"] = val
            item["length"] = length
            item["disp"] = disp
            return
    # Insert before sub-nodes
    insert_idx = 0
    for idx, item in enumerate(node_list):
        if isinstance(item, dict):
            insert_idx = idx + 1
        else:
            break
    node_list.insert(
        insert_idx,
        {"name": name, "length": length, "flags": 0, "disp": disp, "value": val},
    )


def remove_prop(node_list: list, name: str) -> bool:
    for item in list(node_list):
        if isinstance(item, dict) and item.get("name") == name:
            node_list.remove(item)
            return True
    return False


def collect_phandles(items: list, out: list):
    for item in items:
        if isinstance(item, list):
            collect_phandles(item, out)
        elif isinstance(item, dict) and item.get("name") == "AAPL,phandle":
            out.append(item.get("value", 0))


def port_filesystems(tree: dict, donor_path=None):
    """Port /filesystems + /osenvironments from the N66AP iOS 13 donor into the
    already-patched base tree (in place) and adjust vol.fs_role entries to
    match this device's on-disk roles."""
    donor_tree = load_jsonc(donor_path or N66_JSONC)
    base_root = tree["device-tree"]
    donor_root = donor_tree["device-tree"]

    # --- phandle collision check -------------------------------------------
    # Only the phandles *inside the ported nodes* need to be collision-free;
    # the donor DT as a whole obviously reuses low numbers internally.
    base_ph, ported_ph = [], []
    collect_phandles(base_root, base_ph)
    for name in PORTED_TOP_NODES:
        donor_node = find_top_node(donor_root, name)
        if donor_node is not None:
            collect_phandles(donor_node, ported_ph)
    base_max = max(base_ph) if base_ph else 0
    ported_min = min(ported_ph) if ported_ph else 0
    ported_max = max(ported_ph) if ported_ph else 0
    if ported_ph and ported_min <= base_max:
        sys.exit(
            f"ERROR: phandle collision (base max={base_max}, ported range="
            f"{ported_min}..{ported_max}). Renumber the ported nodes before repacking."
        )
    print(
        f"  ✓ Phandle check OK (base max={base_max} < ported range {ported_min}..{ported_max})"
    )

    # --- port nodes ---------------------------------------------------------
    for name in PORTED_TOP_NODES:
        donor_node = find_top_node(donor_root, name)
        if donor_node is None:
            sys.exit(f"ERROR: donor DT has no top-level '{name}' node")
        if find_top_node(base_root, name) is not None:
            print(f"  • '{name}' already present in base DT, skipping port")
            continue
        base_root.append(copy.deepcopy(donor_node))
        print(f"  ✓ Ported /{name} from N66AP donor")

    # --- adjust fstab roles --------------------------------------------------
    fstab = find_node_by_path(base_root, ["filesystems", "fstab"])
    if fstab is None:
        sys.exit("ERROR: /filesystems/fstab not found after port")

    role_patches = []  # (volume name, expected original role, new role)
    for entry in fstab:
        if not isinstance(entry, list):
            continue
        props = {p["name"]: p for p in entry if isinstance(p, dict)}
        vol_name = props.get("vol.fs_name", {}).get("value")
        role_prop = props.get("vol.fs_role")
        if vol_name == "System" and role_prop:
            role_patches.append(("System", role_prop.get("value"), SYSTEM_VOL_ROLE))
            role_prop["value"] = SYSTEM_VOL_ROLE
        elif vol_name == "Data" and role_prop:
            role_patches.append(("Data", role_prop.get("value"), DATA_VOL_ROLE))
            role_prop["value"] = DATA_VOL_ROLE

    for vol, old, new in role_patches:
        print(f"  ✓ fstab {vol}-vol: vol.fs_role {old} -> {new}")

    # Drop entries for volumes this container doesn't have (xART 0x100,
    # Update 0xC0).  Baseband-Data (role 0x80 -> disk0s1s3) is kept so launchd
    # mounts it at /private/var/wireless/baseband_data for the cellular stack.
    keep = {"System", "Data", "Baseband-Data"}
    for entry in [e for e in fstab if isinstance(e, list)]:
        props = {p["name"]: p for p in entry if isinstance(p, dict)}
        vol_name = props.get("vol.fs_name", {}).get("value")
        if vol_name not in keep:
            fstab.remove(entry)
            role = props.get("vol.fs_role", {}).get("value")
            print(f"  ✓ fstab: removed {vol_name} (role 0x{role:x})")


def patch_native(base_path=None, donor_path=None, out_json=None, out_binary=None, repack=None):
    base_path = base_path or N56_JSONC
    out_json = out_json or OUT_JSONC
    out_binary = out_binary or OUT_BIN
    print(f"Loading native N56AP DeviceTree: {base_path}")
    tree = load_jsonc(base_path)
    root = tree["device-tree"]

    # 1. Patch /chosen with iOS 13 required properties
    #    (list verified against real j96ap/n66ap iOS 13 DTs)
    chosen = find_node_by_path(root, ["chosen"])
    if chosen is None:
        sys.exit("ERROR: /chosen not found!")

    chosen_props = [
        ("amfi-allows-trust-cache-load", 0, 4, 1),
        ("amfi-only-platform-code", 0, 4, 1),
        ("disable-accessory-firmware", 0, 4, 1),
        ("disable-av-content-protection", 0, 4, 1),
        ("disable-transport-rm", 0, 4, 1),
        ("display-boot-rotation", 0, 4, 1),
        ("ephemeral-storage", 0, 4, 1),
        ("max-env-partition", 0, 4, 1),
        ("max-env-var-data-size", 0, 4, 1),
        ("max-env-var-name-size", 0, 4, 1),
        ("osenvironment", "", 32, 3),
        ("protected-data-access", 1, 4, 1),
        ("sepfw-load-at-boot", 1, 4, 1),
        ("use-recovery-securityd", 0, 4, 1),
    ]

    for name, val, length, disp in chosen_props:
        add_prop(chosen, name, val, length, disp)
    print(f"  ✓ Patched /chosen with {len(chosen_props)} donor properties")

    # NOTE: boot volume selection (disk0s1s4) is done at the iBoot level via
    # the boot-arg `rd=disk0s1s4` in the patched iBEC — NOT via DeviceTree.
    # Real iOS 13 DeviceTrees carry no boot-partition property in /chosen.

    # 2. Port /filesystems (DT fstab) + /osenvironments from N66AP iOS 13
    port_filesystems(tree, donor_path)
    root = tree["device-tree"]

    # 3. Patch /arm-io/sep/iop-sep-nub
    sep_nub = find_node_by_path(root, ["arm-io", "sep", "iop-sep-nub"])
    if sep_nub:
        add_prop(sep_nub, "rom-panic-bytes", 0, 4, 1)
        print("  ✓ Added rom-panic-bytes to /arm-io/sep/iop-sep-nub")

    # 4. Patch touch compatibility alias (multi-touch,n56 -> add multi-touch,j96 fallback)
    touch_node = find_node_by_path(root, ["arm-io", "spi2", "multi-touch"])
    if touch_node:
        add_prop(
            touch_node,
            "compatible",
            "multi-touch,n56\x00multi-touch,j96\x00",
            32,
            4,
        )
        print("  ✓ Added multi-touch,j96 alias to /arm-io/spi2/multi-touch")

        # Drop function-power_ana (analog supply for the touch controller).
        # Its provider is display-pmu,chestnut (phandle 0x4b), a TI display PMU
        # that has NO driver in the j96 iOS 13 kernel (IOFunctionParent0000004B
        # is absent; the node is only claimed by the generic AppleARMIICDevice).
        # So this platform-function never gets a provider and
        # AppleMultitouchN1SPI::start blocks forever (multi-touch@0 stays
        # !matched/busy 1, ResetCount=0). The rail is already powered by iBoot:
        # the display works and lcd's lcd_ldo — same chestnut provider — is
        # likewise unbacked yet the panel runs. Removing this redundant
        # dependency lets start proceed past the power stage; the other touch
        # functions keep their present providers (power_ldo→pmu 0x49,
        # clock_enable→pmgr 0x13, reset/enable_cs→gpio 0x18).
        # 现已把 AppleChestnutDisplayPMU kext 从 n66 移植进 j96 内核
        # (chestnut_port/inject_chestnut.py), 它会为 display-pmu,chestnut 提供
        # AppleDisplayPMUFunctionLDOEnable = power_ana。所以默认【保留】
        # function-power_ana, 让触摸驱动真正拿到模拟供电。
        # 仅当 DROP_POWER_ANA=1 时才删除 (旧实验: 内核未注入 chestnut 的回退)。
        if os.environ.get("DROP_POWER_ANA") == "1":
            if remove_prop(touch_node, "function-power_ana"):
                print("  ✓ [DROP_POWER_ANA=1] Removed function-power_ana "
                      "(fallback: kernel without chestnut kext)")
            else:
                print("  • function-power_ana not present on touch node (skipped)")
        else:
            print("  ✓ Kept function-power_ana (chestnut kext now provides it)")

    # 5. Adapt the N56 Stockholm GPIO schema to the iOS 13 NFC driver.
    stockholm = find_node_by_path(root, ["arm-io", "uart3", "stockholm"])
    if stockholm:
        enable = next(
            (item for item in stockholm
             if isinstance(item, dict) and item.get("name") == "function-enable"),
            None,
        )
        if enable:
            add_prop(stockholm, "function-enable-gpio", enable["value"],
                     enable["length"], enable["disp"])
        required = (
            "support_wake_stockholm\x00"
            "support_venable\x00"
            "support_download_request\x00"
        )
        add_prop(stockholm, "required-gpios", required, len(required), 4)
        print("  ✓ Added Stockholm GPIO aliases")

    # 6. Save output
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2, ensure_ascii=False)
    print(f"  ✓ Saved native patched JSONC: {out_json}")

    # 7. Repack to binary
    subprocess.run([repack or repack_tool, out_json, out_binary], check=True)
    print(f"DeviceTree: {out_binary} ({os.path.getsize(out_binary)} B)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the N56 iOS 13 DeviceTree")
    parser.add_argument("--repack", required=True)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    OUT_JSONC = str(args.out / "DeviceTree.n56_native.jsonc")
    OUT_BIN = str(args.out / "DeviceTree.n56_native.bin")
    repack_tool = args.repack
    patch_native()
