#!/usr/bin/env python3
"""
dt_analyze.py - Apple DeviceTree JSONC analyzer and comparator

Analyzes the output of devicetree-parse for n56ap (iPhone 6 Plus, A8),
j96ap (iPad mini 4, A8), and n66ap (iPhone 6s Plus, A9) device trees.

Usage:
    python3 dt_analyze.py [--diff n56ap j96ap] [--node <nodename>] [--list n56ap]
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from paths import DERIVED, WORK

EXTRACTED = DERIVED / "extracted"

DT_PATHS = {
    "n56ap": os.path.join(EXTRACTED, "n56ap_ios12", "DeviceTree.n56ap.jsonc"),
    "j96ap": os.path.join(EXTRACTED, "j96ap_ios13", "DeviceTree.j96ap.jsonc"),
    "n66ap": os.path.join(EXTRACTED, "n66ap_ios13", "DeviceTree.n66ap.jsonc"),
}

# ---------------------------------------------------------------------------
# JSONC loader  (devicetree-parse output has trailing commas; no real comments)
# ---------------------------------------------------------------------------


def load_jsonc(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        content = f.read()
    # Strip trailing commas before ] or }
    content = re.sub(r",(\s*[}\]])", r"\1", content)
    return json.loads(content)


# ---------------------------------------------------------------------------
# Tree traversal helpers
# ---------------------------------------------------------------------------


def node_name(node_list: list) -> str:
    """Return the value of the 'name' property in a node array."""
    for item in node_list:
        if isinstance(item, dict) and item.get("name") == "name":
            return str(item.get("value", ""))
    return ""


def node_props(node_list: list) -> dict:
    """Return all non-child properties of a node as {propname: entry}."""
    props = {}
    for item in node_list:
        if isinstance(item, dict):
            n = item.get("name")
            if n:
                props[n] = item
    return props


def child_nodes(node_list: list) -> list:
    """Return all direct child node arrays."""
    return [item for item in node_list if isinstance(item, list)]


def walk_tree(items: list, path: str = "") -> list[tuple[str, list]]:
    """
    Walk the tree and yield (path, node_list) for every node.
    The device-tree root list is passed as `items`.
    """
    result = []
    for item in items:
        if isinstance(item, list):
            name = node_name(item)
            full_path = f"{path}/{name}" if name else f"{path}/?"
            result.append((full_path, item))
            result.extend(walk_tree(item, full_path))
    return result


def find_node(
    items: list, target_name: str, path: str = ""
) -> Optional[tuple[str, list]]:
    """Find first node whose 'name' property equals target_name."""
    for item in items:
        if isinstance(item, list):
            name = node_name(item)
            full_path = f"{path}/{name}" if name else f"{path}/?"
            if name == target_name:
                return (full_path, item)
            result = find_node(item, target_name, full_path)
            if result:
                return result
    return None


def find_node_by_path(items: list, path_parts: list) -> Optional[list]:
    """Walk a path like ['arm-io', 'i2c0'] through the tree."""
    if not path_parts:
        return None
    target = path_parts[0]
    rest = path_parts[1:]
    for item in items:
        if isinstance(item, list):
            name = node_name(item)
            if name == target:
                if not rest:
                    return item
                return find_node_by_path(item, rest)
    return None


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def fmt_value(entry: dict) -> str:
    v = entry.get("value")
    disp = entry.get("disp", 0)
    length = entry.get("length", 0)
    if v is None:
        return "<empty>"
    if isinstance(v, int):
        if disp == 1:
            return f"0x{v:x} ({v})"
        elif disp == 2:
            return f"{v}"
        else:
            return f"0x{v:x}"
    if isinstance(v, str):
        if len(v) > 80:
            return repr(v[:80]) + "..."
        return repr(v)
    return str(v)


def fmt_prop(entry: dict, indent: int = 2) -> str:
    pad = " " * indent
    name = entry.get("name", "?")
    length = entry.get("length", 0)
    flags = entry.get("flags", 0)
    val = fmt_value(entry)
    return f"{pad}{name:<40}  len={length:<6} flags=0x{flags:04x}  val={val}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list(args):
    """List all nodes in a device tree."""
    key = args.tree
    path = DT_PATHS.get(key)
    if not path or not os.path.exists(path):
        print(f"ERROR: {key} device tree not found at {path}")
        sys.exit(1)
    dt = load_jsonc(path)
    root = dt["device-tree"]
    nodes = walk_tree(root)
    print(f"\n=== All nodes in {key} ({len(nodes)} total) ===\n")
    for node_path, _ in nodes:
        print(f"  {node_path}")


def cmd_show_node(args):
    """Show all properties of a named node across one or more trees."""
    target = args.node
    trees = args.trees if args.trees else list(DT_PATHS.keys())

    for key in trees:
        path = DT_PATHS.get(key)
        if not path or not os.path.exists(path):
            print(f"[{key}] NOT FOUND ({path})")
            continue
        dt = load_jsonc(path)
        root = dt["device-tree"]
        result = find_node(root, target)
        if result is None:
            print(f"\n[{key}] Node '{target}' NOT FOUND")
            continue
        found_path, node = result
        props = node_props(node)
        children = child_nodes(node)
        print(
            f"\n[{key}] Node '{found_path}'  ({len(props)} props, {len(children)} children)"
        )
        for pname, entry in sorted(props.items()):
            print(fmt_prop(entry))


def cmd_diff(args):
    """
    Compare two device trees:
    - Nodes present in A but missing in B
    - Nodes present in B but missing in A
    - Nodes in both but with differing properties
    """
    key_a, key_b = args.trees[0], args.trees[1]
    for key in (key_a, key_b):
        path = DT_PATHS.get(key)
        if not path or not os.path.exists(path):
            print(f"ERROR: {key} device tree not found at {path}")
            sys.exit(1)

    dt_a = load_jsonc(DT_PATHS[key_a])
    dt_b = load_jsonc(DT_PATHS[key_b])
    root_a = dt_a["device-tree"]
    root_b = dt_b["device-tree"]

    nodes_a = {p: n for p, n in walk_tree(root_a)}
    nodes_b = {p: n for p, n in walk_tree(root_b)}

    all_paths = sorted(set(nodes_a.keys()) | set(nodes_b.keys()))

    only_a = sorted(p for p in all_paths if p in nodes_a and p not in nodes_b)
    only_b = sorted(p for p in all_paths if p in nodes_b and p not in nodes_a)
    both = sorted(p for p in all_paths if p in nodes_a and p in nodes_b)

    print(f"\n=== DeviceTree diff: [{key_a}] vs [{key_b}] ===\n")

    print(f"--- Nodes only in {key_a} ({len(only_a)}) ---")
    for p in only_a:
        print(f"  < {p}")

    print(f"\n--- Nodes only in {key_b} ({len(only_b)}) ---")
    for p in only_b:
        print(f"  > {p}")

    # Property-level diff for nodes that exist in both
    diff_nodes = []
    for p in both:
        props_a = node_props(nodes_a[p])
        props_b = node_props(nodes_b[p])
        all_props = sorted(set(props_a.keys()) | set(props_b.keys()))
        diffs = []
        for prop in all_props:
            if prop == "AAPL,phandle":
                continue  # phandle values always differ, skip
            if prop in props_a and prop not in props_b:
                diffs.append(f"    < {prop}  (only in {key_a})")
            elif prop in props_b and prop not in props_a:
                diffs.append(f"    > {prop}  (only in {key_b})")
            else:
                va = props_a[prop].get("value")
                vb = props_b[prop].get("value")
                if va != vb:
                    diffs.append(f"    ~ {prop}")
                    diffs.append(f"        [{key_a}] {fmt_value(props_a[prop])}")
                    diffs.append(f"        [{key_b}] {fmt_value(props_b[prop])}")
        if diffs:
            diff_nodes.append((p, diffs))

    print(f"\n--- Nodes in both with property differences ({len(diff_nodes)}) ---")
    for p, diffs in diff_nodes:
        print(f"\n  {p}")
        for line in diffs:
            print(line)

    print(
        f"\nSummary: only_in_{key_a}={len(only_a)}  only_in_{key_b}={len(only_b)}  "
        f"both={len(both)}  differ={len(diff_nodes)}"
    )


def cmd_merge_plan(args):
    """
    Print the recommended merge plan: which n56ap nodes should be injected
    into the j96ap tree, with rationale.

    Strategy: use j96ap iOS 13 as base, transplant n56ap hardware-specific nodes.
    n66ap is used as a reference to understand which nodes are iPhone-specific
    (n66ap = iPhone 6s Plus, iOS 13, A9 — shares iPhone form factor with n56ap).
    """
    for key in ("n56ap", "j96ap", "n66ap"):
        path = DT_PATHS.get(key)
        if not path or not os.path.exists(path):
            print(f"WARNING: {key} not found, merge plan may be incomplete")

    print("""
=== DeviceTree Merge Plan ===

Goal: Boot iOS 13 (j96ap base) on iPhone 6 Plus (n56ap hardware, A8 chip).

n56ap = iPhone 6 Plus  (A8, t7000, iOS 12.5.8)
j96ap = iPad mini 4    (A8, t7000, iOS 13.7)   <-- base OS
n66ap = iPhone 6s Plus (A9, s8000, iOS 13.7)   <-- iPhone 13 driver reference

Since n56ap and j96ap share the exact same SoC (Apple A8 / t7000),
memory maps and register addresses are compatible.  The merge only needs to
replace hardware-topology nodes that differ between the two form factors.

--- MUST REPLACE from n56ap → into j96ap base ---

  /arm-io/display0
      LCD controller registers differ (display resolution, timing).
      n56ap: 1242×2208 (3× iPhone)
      j96ap: 2048×1536 (2× iPad mini)

  /arm-io/disp0
      Display pipe / scaler — form-factor specific.

  /arm-io/backlight-control   (or backlight)
      PWM duty cycle range is display-specific.

  /arm-io/i2c0
      Touch controller I2C — Melfas vs Synaptics, different slave addresses.

  /arm-io/i2c1
      Sensor hub I2C — proximity, ambient light (different on phone vs tablet).

  /arm-io/uart1
      Baseband UART (Qualcomm MDM) — pin assignment differs.

  /arm-io/gpio
      Home button, volume, power — iPhone button layout differs from iPad.

--- SHOULD REPLACE (for correct peripheral init) ---

  /arm-io/mipi-dsim0  (MIPI DSI host controller - display bus)
  /arm-io/spi1        (NOR flash / touch firmware update)
  /arm-io/audio-controller  (Cirrus CS42L51 on n56ap vs Realtek on j96ap)

--- KEEP from j96ap base (OS-level, chip-universal) ---

  /arm-io/dma-controller   (same A8 DMA engine)
  /arm-io/timer            (same ARM timer)
  /arm-io/watchdog         (same)
  /arm-io/usb-device       (Lightning controller)
  /arm-io/nand             (NAND flash controller - universal)
  /cpus                    (A8 core config - identical between devices)

--- PATCH (in-place property edits, not whole-node replace) ---

  /  (root)
      compatible: change "iPad5,1\\x00AppleARM" → "iPhone7,1\\x00AppleARM"
      target-type: change "J96" → "N56"
      model: change "iPad5,1" → "iPhone7,1"

  /product
      artwork-device-idiom: change "pad" → "phone"
      artwork-device-subtype: adjust for iPhone 6 Plus (value 0x0)

--- REFERENCE: n66ap iOS 13 ---

  The n66ap tree has iPhone 6s Plus hardware under iOS 13.
  For nodes where n56ap (iOS 12) and j96ap (iOS 13) schemas differ,
  consult n66ap to understand the iOS 13 schema for iPhone-form-factor nodes.
  Specifically useful for:
    - EventTimingProfiles (touch panel timing)
    - display0 node property names that changed between iOS 12→13
    - baseband uart configuration
""")


def cmd_extract_node(args):
    """
    Extract a specific node from a tree as JSON (for use in merge scripts).
    """
    key = args.tree
    target = args.node
    path = DT_PATHS.get(key)
    if not path or not os.path.exists(path):
        print(f"ERROR: {key} not found")
        sys.exit(1)
    dt = load_jsonc(path)
    result = find_node(dt["device-tree"], target)
    if result is None:
        print(f"Node '{target}' not found in {key}")
        sys.exit(1)
    found_path, node = result
    print(f"# Node '{found_path}' from {key}")
    print(json.dumps(node, indent=2))


def cmd_prop_diff(args):
    """
    For a specific node name that exists in multiple trees,
    show a clean property-level diff.
    """
    target = args.node
    trees = args.trees if args.trees else ["n56ap", "j96ap", "n66ap"]
    data = {}
    for key in trees:
        path = DT_PATHS.get(key)
        if not path or not os.path.exists(path):
            continue
        dt = load_jsonc(path)
        result = find_node(dt["device-tree"], target)
        if result:
            _, node = result
            data[key] = node_props(node)

    if not data:
        print(f"Node '{target}' not found in any tree")
        sys.exit(1)

    all_props = sorted(set().union(*[set(p.keys()) for p in data.values()]))
    all_keys = list(data.keys())

    print(f"\n=== Property diff for node '{target}' ===")
    print(f"Trees: {', '.join(all_keys)}\n")

    col_w = 38
    header = f"  {'Property':<{col_w}}" + "".join(f"  {k:<30}" for k in all_keys)
    print(header)
    print("  " + "-" * (col_w + 32 * len(all_keys)))

    for prop in all_props:
        if prop == "AAPL,phandle":
            continue
        vals = {}
        for k in all_keys:
            if k in data and prop in data[k]:
                vals[k] = fmt_value(data[k][prop])
            else:
                vals[k] = "<missing>"

        unique_vals = set(vals.values())
        marker = "  " if len(unique_vals) == 1 else "* "
        row = f"{marker}{prop:<{col_w}}" + "".join(
            f"  {vals.get(k, '<missing>'):<30}" for k in all_keys
        )
        print(row)

    print()
    # Summary
    n_same = 0
    n_diff = 0
    n_missing = 0
    for prop in all_props:
        if prop == "AAPL,phandle":
            continue
        present = [k for k in all_keys if k in data and prop in data[k]]
        if len(present) < len(all_keys):
            n_missing += 1
        elif len(set(fmt_value(data[k][prop]) for k in present)) > 1:
            n_diff += 1
        else:
            n_same += 1
    print(
        f"  same={n_same}  different={n_diff}  missing_in_some={n_missing}  (* = differs)"
    )


def cmd_summary(args):
    """Print a high-level summary of all three trees."""
    print("\n=== Device Tree Summary ===\n")
    for key, path in DT_PATHS.items():
        if not os.path.exists(path):
            print(f"  {key:<10}  NOT FOUND ({path})")
            continue
        dt = load_jsonc(path)
        root = dt["device-tree"]
        all_nodes = walk_tree(root)

        # Count properties at root level
        root_props = node_props(root)

        # Get device identity
        compatible = ""
        model = ""
        target_type = ""
        for item in root:
            if isinstance(item, dict):
                if item.get("name") == "compatible":
                    compatible = str(item.get("value", "")).replace("\\x00", "|")
                elif item.get("name") == "model":
                    model = str(item.get("value", ""))
                elif item.get("name") == "target-type":
                    target_type = str(item.get("value", ""))

        print(
            f"  {key:<10}  model={model:<20} target={target_type:<10} "
            f"nodes={len(all_nodes):<5} root_props={len(root_props)}"
        )
        print(f"             compatible: {compatible}")

    print()
    print("SoC mapping:")
    print("  n56ap  = t7000  = Apple A8  (iPhone 6 Plus, iOS 12.5.8)")
    print("  j96ap  = t7000  = Apple A8  (iPad mini 4,   iOS 13.7)  <-- SAME CHIP")
    print(
        "  n66ap  = s8000  = Apple A9  (iPhone 6s Plus, iOS 13.7) <-- iPhone reference"
    )
    print()
    print("Since n56ap and j96ap share the A8 (t7000) SoC, boot chain is compatible.")
    print(
        "Device tree merge is needed only for peripheral/hardware topology differences."
    )


def cmd_arm_io_compare(args):
    """Compare arm-io sub-nodes across trees — the most important section."""
    trees_to_compare = args.trees if args.trees else ["n56ap", "j96ap", "n66ap"]
    data = {}
    for key in trees_to_compare:
        path = DT_PATHS.get(key)
        if not path or not os.path.exists(path):
            continue
        dt = load_jsonc(path)
        arm_io = find_node(dt["device-tree"], "arm-io")
        if arm_io is None:
            print(f"  WARNING: arm-io not found in {key}")
            continue
        _, node = arm_io
        # Collect child node names of arm-io
        children = {}
        for item in node:
            if isinstance(item, list):
                n = node_name(item)
                if n:
                    children[n] = item
        data[key] = children

    if not data:
        print("No arm-io nodes found")
        return

    all_keys = list(data.keys())
    all_children = sorted(set().union(*[set(c.keys()) for c in data.values()]))

    print(f"\n=== arm-io sub-nodes comparison ===")
    print(f"Trees: {', '.join(all_keys)}\n")
    print(f"  {'Node name':<35}", end="")
    for k in all_keys:
        print(f"  {k:<12}", end="")
    print()
    print("  " + "-" * (35 + 14 * len(all_keys)))

    for child in all_children:
        row = f"  {child:<35}"
        presence = []
        for k in all_keys:
            if child in data[k]:
                row += f"  {'yes':<12}"
                presence.append(k)
            else:
                row += f"  {'---':<12}"
        # Mark nodes unique to a single tree
        if len(presence) == 1:
            row += f"  <-- only in {presence[0]}"
        print(row)

    print()
    for k in all_keys:
        print(f"  {k}: {len(data[k])} arm-io children")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Analyze and compare Apple DeviceTree JSONC files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  summary                    High-level overview of all trees
  list   <tree>              List all nodes in a tree
  show   <node> [trees...]   Show properties of a named node
  diff   <tree_a> <tree_b>   Full structural diff between two trees
  propdiff <node> [trees...] Property-level diff for a named node
  armio  [trees...]          Compare arm-io sub-nodes (key section)
  extract <tree> <node>      Extract node as JSON (for merge scripts)
  plan                       Print recommended merge plan

Examples:
  python3 dt_analyze.py summary
  python3 dt_analyze.py diff n56ap j96ap
  python3 dt_analyze.py show arm-io n56ap j96ap
  python3 dt_analyze.py propdiff display0 n56ap j96ap n66ap
  python3 dt_analyze.py armio n56ap j96ap n66ap
  python3 dt_analyze.py plan
  python3 dt_analyze.py extract n56ap display0 > display0_n56.json
        """,
    )

    sub = parser.add_subparsers(dest="command")

    p_summary = sub.add_parser("summary")

    p_list = sub.add_parser("list")
    p_list.add_argument("tree", choices=list(DT_PATHS.keys()))

    p_show = sub.add_parser("show")
    p_show.add_argument("node")
    p_show.add_argument("trees", nargs="*")

    p_diff = sub.add_parser("diff")
    p_diff.add_argument("trees", nargs=2)

    p_propdiff = sub.add_parser("propdiff")
    p_propdiff.add_argument("node")
    p_propdiff.add_argument("trees", nargs="*")

    p_armio = sub.add_parser("armio")
    p_armio.add_argument("trees", nargs="*")

    p_extract = sub.add_parser("extract")
    p_extract.add_argument("tree", choices=list(DT_PATHS.keys()))
    p_extract.add_argument("node")

    p_plan = sub.add_parser("plan")

    if len(sys.argv) == 1:
        parser.print_help()
        print("\n  Tip: start with 'python3 dt_analyze.py summary'")
        sys.exit(0)

    args = parser.parse_args()

    dispatch = {
        "summary": cmd_summary,
        "list": cmd_list,
        "show": cmd_show_node,
        "diff": cmd_diff,
        "propdiff": cmd_prop_diff,
        "armio": cmd_arm_io_compare,
        "extract": cmd_extract_node,
        "plan": cmd_merge_plan,
    }

    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        sys.exit(1)

    fn(args)


if __name__ == "__main__":
    main()
