#!/usr/bin/env python3
"""
dt_verify_phandles.py - Verify phandle cross-references in merged device tree

Checks that all iommu-parent and interrupt-parent values in injected/replaced
nodes (from n56ap) correctly resolve to existing nodes in the merged tree.

Usage:
    python3 dt_verify_phandles.py
    python3 dt_verify_phandles.py --verbose
    python3 dt_verify_phandles.py --merged path/to/merged.jsonc
"""

import argparse
import json
import os
import re
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from paths import DERIVED, WORK

EXTRACTED = DERIVED / "extracted"

DEFAULT_N56 = os.path.join(EXTRACTED, "n56ap_ios12", "DeviceTree.n56ap.jsonc")
DEFAULT_J96 = os.path.join(EXTRACTED, "j96ap_ios13", "DeviceTree.j96ap.jsonc")
DEFAULT_MERGED = WORK / "DeviceTree.n56_native.jsonc"

# Nodes that were injected or replaced from n56ap - their cross-refs need checking
INJECTED_NODES = {"i2c1", "mca4", "mipi-dsim", "uart8", "baseband"}
REPLACED_NODES = {"gpio", "i2c0", "i2c2", "spi1", "spi2", "uart1", "uart2"}
ALL_TOUCHED_NODES = INJECTED_NODES | REPLACED_NODES

# Properties that contain phandle references
PHANDLE_REF_PROPS = {"iommu-parent", "interrupt-parent", "clocks", "power-domains"}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def load_jsonc(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        content = f.read()
    content = re.sub(r",(\s*[}\]])", r"\1", content)
    return json.loads(content)


def get_prop(node: list, name: str):
    for item in node:
        if isinstance(item, dict) and item.get("name") == name:
            return item.get("value")
    return None


def find_node(items: list, name: str):
    for item in items:
        if isinstance(item, list):
            for e in item:
                if (
                    isinstance(e, dict)
                    and e.get("name") == "name"
                    and e.get("value") == name
                ):
                    return item
            r = find_node(item, name)
            if r is not None:
                return r
    return None


def walk_tree(items: list, path: str = ""):
    result = []
    for item in items:
        if isinstance(item, list):
            n = get_prop(item, "name") or "?"
            full = f"{path}/{n}"
            result.append((full, item))
            result.extend(walk_tree(item, full))
    return result


def build_phandle_maps(items: list):
    """
    Returns:
        ph_to_name : {phandle_int -> node_name}
        ph_to_path : {phandle_int -> full_path}
        name_to_ph : {node_name -> phandle_int}  (first occurrence)
    """
    ph_to_name = {}
    ph_to_path = {}
    name_to_ph = {}
    for full_path, node in walk_tree(items):
        ph = get_prop(node, "AAPL,phandle")
        n = get_prop(node, "name") or ""
        if ph is not None:
            ph_to_name[ph] = n
            ph_to_path[ph] = full_path
            if n and n not in name_to_ph:
                name_to_ph[n] = ph
    return ph_to_name, ph_to_path, name_to_ph


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_phandles(n56_path, j96_path, merged_path, verbose=False):
    print(f"Loading n56ap   : {n56_path}")
    print(f"Loading j96ap   : {j96_path}")
    print(f"Loading merged  : {merged_path}")
    print()

    dt_n56 = load_jsonc(n56_path)
    dt_j96 = load_jsonc(j96_path)
    dt_merged = load_jsonc(merged_path)

    root_n56 = dt_n56["device-tree"]
    root_j96 = dt_j96["device-tree"]
    root_merged = dt_merged["device-tree"]

    # Build phandle maps
    n56_ph_to_name, n56_ph_to_path, n56_name_to_ph = build_phandle_maps(root_n56)
    j96_ph_to_name, j96_ph_to_path, j96_name_to_ph = build_phandle_maps(root_j96)
    mg_ph_to_name, mg_ph_to_path, mg_name_to_ph = build_phandle_maps(root_merged)

    print(
        f"Phandle map sizes: n56ap={len(n56_ph_to_name)}  j96ap={len(j96_ph_to_name)}  merged={len(mg_ph_to_name)}"
    )
    print()

    errors = []
    warnings = []
    ok_count = 0

    # -----------------------------------------------------------------------
    # 1. For each touched node in the merged tree, check all phandle refs
    # -----------------------------------------------------------------------
    print("=== Checking phandle references in touched nodes ===")
    print()

    for node_name_target in sorted(ALL_TOUCHED_NODES):
        node = find_node(root_merged, node_name_target)
        if node is None:
            if node_name_target in INJECTED_NODES:
                warnings.append(
                    f"Injected node '{node_name_target}' not found in merged tree"
                )
            elif verbose:
                print(f"  [skip] '{node_name_target}' not in merged tree")
            continue

        node_path = f"/arm-io/{node_name_target}"
        tag = "INJ" if node_name_target in INJECTED_NODES else "REP"

        # Collect all phandle-referencing props in this node and children
        def check_node_refs(n, context_path):
            nonlocal ok_count
            refs_found = []
            for item in n:
                if isinstance(item, dict):
                    prop = item.get("name", "")
                    val = item.get("value")
                    if prop in PHANDLE_REF_PROPS and isinstance(val, int):
                        # This phandle should resolve in the merged tree
                        if val in mg_ph_to_name:
                            resolved = mg_ph_to_name[val]
                            resolved_path = mg_ph_to_path[val]
                            refs_found.append(
                                (prop, val, resolved, resolved_path, True)
                            )
                            ok_count += 1
                        else:
                            # Not in merged - check if it was in n56ap
                            if val in n56_ph_to_name:
                                src_name = n56_ph_to_name[val]
                                errors.append(
                                    f"{context_path}.{prop} = phandle 0x{val:x} "
                                    f"resolves to n56ap node '{src_name}' "
                                    f"but that node is NOT in merged tree!"
                                )
                                refs_found.append(
                                    (
                                        prop,
                                        val,
                                        f"n56ap::{src_name}",
                                        "NOT IN MERGED",
                                        False,
                                    )
                                )
                            elif val in j96_ph_to_name:
                                src_name = j96_ph_to_name[val]
                                # phandle from j96 - might be a stale ref
                                warnings.append(
                                    f"{context_path}.{prop} = phandle 0x{val:x} "
                                    f"is a j96ap-only phandle ('{src_name}') "
                                    f"but not in merged - may have been dropped"
                                )
                                refs_found.append(
                                    (prop, val, f"j96ap::{src_name}", "DROPPED?", False)
                                )
                            else:
                                errors.append(
                                    f"{context_path}.{prop} = phandle 0x{val:x} "
                                    f"does not resolve in ANY tree!"
                                )
                                refs_found.append((prop, val, "???", "UNKNOWN", False))
                elif isinstance(item, list):
                    child_name = get_prop(item, "name") or "?"
                    check_node_refs(item, f"{context_path}/{child_name}")
            return refs_found

        refs = check_node_refs(node, node_path)

        if refs:
            print(f"  [{tag}] {node_path}")
            for prop, val, resolved, resolved_path, ok in refs:
                mark = "✓" if ok else "✗"
                print(f"       {mark} .{prop} = phandle 0x{val:x} → {resolved}")
                if verbose and ok:
                    print(f"         (at {resolved_path})")
            print()
        elif verbose:
            print(f"  [{tag}] {node_path} — no phandle refs")
            print()

    # -----------------------------------------------------------------------
    # 2. Check AIC (interrupt controller) phandle consistency
    # -----------------------------------------------------------------------
    print("=== AIC (interrupt controller) phandle consistency ===")
    aic_n56 = n56_name_to_ph.get("aic")
    aic_j96 = j96_name_to_ph.get("aic")
    aic_merged = mg_name_to_ph.get("aic")

    def ph_str(v):
        return f"0x{v:x}" if v is not None else "NOT FOUND"

    print(f"  n56ap   AIC phandle: {ph_str(aic_n56)}")
    print(f"  j96ap   AIC phandle: {ph_str(aic_j96)}")
    print(f"  merged  AIC phandle: {ph_str(aic_merged)}")

    if aic_merged is None:
        errors.append("AIC node not found in merged tree!")
    elif aic_merged == aic_j96:
        print(f"  ✓ Merged AIC phandle matches j96ap (0x{aic_j96:x})")
        if aic_n56 != aic_j96:
            print(
                f"  ✓ Nodes from n56ap with AIC refs should have been remapped "
                f"(0x{aic_n56:x} → 0x{aic_j96:x})"
            )
    else:
        warnings.append(
            f"Merged AIC phandle (0x{aic_merged:x}) differs from both n56ap and j96ap"
        )
    print()

    # -----------------------------------------------------------------------
    # 3. Check dart-* (IOMMU) phandle consistency for injected nodes
    # -----------------------------------------------------------------------
    print("=== DART (IOMMU) phandle consistency ===")
    dart_nodes = [k for k in mg_name_to_ph if k.startswith("dart-")]
    print(f"  DART nodes in merged tree: {', '.join(sorted(dart_nodes))}")

    # The injected i2c1 uses interrupt-parent (AIC), not iommu-parent
    # But mipi-dsim uses dart-disp0 as iommu-parent
    mipi = find_node(root_merged, "mipi-dsim")
    if mipi:
        iommu_ph = get_prop(mipi, "iommu-parent")
        if iommu_ph is not None:
            resolved = mg_ph_to_name.get(iommu_ph, "UNKNOWN")
            path = mg_ph_to_path.get(iommu_ph, "?")
            ok = iommu_ph in mg_ph_to_name
            mark = "✓" if ok else "✗"
            print(f"  {mark} mipi-dsim.iommu-parent = 0x{iommu_ph:x} → {resolved}")
            if not ok:
                errors.append(
                    f"mipi-dsim.iommu-parent = 0x{iommu_ph:x} not resolved in merged!"
                )
    print()

    # -----------------------------------------------------------------------
    # 4. Global phandle uniqueness check (no duplicates in merged)
    # -----------------------------------------------------------------------
    print("=== Global phandle uniqueness in merged tree ===")
    all_nodes = walk_tree(root_merged)
    phandle_seen = {}
    dup_errors = []
    for full_path, node in all_nodes:
        ph = get_prop(node, "AAPL,phandle")
        if ph is None:
            continue
        if ph in phandle_seen:
            dup_errors.append(
                f"Duplicate phandle 0x{ph:x}: '{phandle_seen[ph]}' and '{full_path}'"
            )
        else:
            phandle_seen[ph] = full_path

    if dup_errors:
        for e in dup_errors:
            errors.append(e)
        print(f"  ✗ {len(dup_errors)} duplicate phandle(s) found!")
        for e in dup_errors:
            print(f"    {e}")
    else:
        print(f"  ✓ All {len(phandle_seen)} phandles in merged tree are unique")
    print()

    # -----------------------------------------------------------------------
    # 5. Key cross-reference table
    # -----------------------------------------------------------------------
    print("=== Key phandle cross-reference table ===")
    print()
    important = [
        "aic",
        "aic-timebase",
        "dart-disp0",
        "dart-isp",
        "dart-jpeg",
        "dart-scaler",
        "dart-ave",
        "gpio",
        "pmgr",
        "sep",
    ]
    col = 30
    print(
        f"  {'Node':<{col}}  {'n56ap ph':<12}  {'j96ap ph':<12}  {'merged ph':<12}  Match?"
    )
    print("  " + "-" * 72)
    for nm in important:
        ph_n56 = n56_name_to_ph.get(nm)
        ph_j96 = j96_name_to_ph.get(nm)
        ph_mg = mg_name_to_ph.get(nm)
        s_n56 = f"0x{ph_n56:x}" if ph_n56 is not None else "---"
        s_j96 = f"0x{ph_j96:x}" if ph_j96 is not None else "---"
        s_mg = f"0x{ph_mg:x}" if ph_mg is not None else "---"
        # merged should match j96ap (it's the base)
        match = "✓" if ph_mg == ph_j96 else ("~" if ph_mg is not None else "✗")
        print(f"  {nm:<{col}}  {s_n56:<12}  {s_j96:<12}  {s_mg:<12}  {match}")
    print()

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("=== Summary ===")
    print(f"  OK checks       : {ok_count}")
    print(f"  Errors          : {len(errors)}")
    print(f"  Warnings        : {len(warnings)}")
    print()

    if warnings:
        print("Warnings:")
        for w in warnings:
            print(f"  ! {w}")
        print()

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  ✗ {e}")
        print()
        print("The merged device tree has phandle reference errors.")
        print("Run 'python3 dt_merge.py' to regenerate with corrected remapping.")
        sys.exit(1)
    else:
        print("✓ All phandle references in touched nodes resolve correctly.")
        print("  The merged device tree is internally consistent.")
        sys.exit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Verify phandle cross-references in the merged n56ap+j96ap device tree",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool checks that every iommu-parent and interrupt-parent value
in nodes that were injected or replaced from n56ap (iPhone 6 Plus)
correctly resolves to an existing node in the merged device tree.

Common issues it detects:
  - Stale n56ap phandles that were not remapped during merge
  - Duplicate phandle values (would cause kernel DT parse failure)
  - Missing DART/IOMMU targets for injected peripheral nodes
  - AIC (interrupt controller) phandle inconsistency

Examples:
  python3 dt_verify_phandles.py
  python3 dt_verify_phandles.py --verbose
  python3 dt_verify_phandles.py --merged build/DeviceTree.n56_native.jsonc
        """,
    )
    parser.add_argument(
        "--n56",
        default=DEFAULT_N56,
        metavar="FILE",
        help=f"n56ap device tree JSONC (default: {DEFAULT_N56})",
    )
    parser.add_argument(
        "--j96",
        default=DEFAULT_J96,
        metavar="FILE",
        help=f"j96ap device tree JSONC (default: {DEFAULT_J96})",
    )
    parser.add_argument(
        "--merged",
        default=DEFAULT_MERGED,
        metavar="FILE",
        help=f"Merged device tree JSONC (default: {DEFAULT_MERGED})",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show additional detail for passing checks",
    )

    args = parser.parse_args()

    for label, path in [
        ("--n56", args.n56),
        ("--j96", args.j96),
        ("--merged", args.merged),
    ]:
        if not os.path.exists(path):
            print(f"ERROR: {label} file not found: {path}", file=sys.stderr)
            print(
                "  Run ./setup.sh extract && python3 dt_merge.py first.",
                file=sys.stderr,
            )
            sys.exit(1)

    verify_phandles(
        n56_path=args.n56,
        j96_path=args.j96,
        merged_path=args.merged,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
