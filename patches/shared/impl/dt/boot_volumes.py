"""Bind System/Data fstab entries to explicit N56 APFS slices."""
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path


def validate_slices(system, data):
    if not 3 <= system <= 100 or not 3 <= data <= 100:
        raise ValueError("独立系统使用 s3–s100")
    if system == data:
        raise ValueError("System 和 Data 需要不同的卷号")


def bind_tree(tree, system, data):
    validate_slices(system, data)
    fstab = find_node_by_path(tree["device-tree"], ["filesystems", "fstab"])
    devices = {"System": system, "Data": data}
    found = set()
    for entry in fstab:
        if not isinstance(entry, list):
            continue
        props = {p["name"]: p for p in entry if isinstance(p, dict)}
        name = props.get("vol.fs_name", {}).get("value")
        if name in devices:
            device = f"/dev/disk0s1s{devices[name]}"
            add_prop(entry, "vol.fs_spec", device, len(device) + 1, 3)
            found.add(name)
    if found != set(devices):
        raise ValueError("DeviceTree fstab 需要 System 和 Data 条目")
    return {name: f"/dev/disk0s1s{slice_no}" for name, slice_no in devices.items()}
