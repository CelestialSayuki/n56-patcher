# -*- coding: utf-8 -*-
"""Cross-platform arguments for local tar creation.

macOS BSD tar uses ``--uid``/``--gid`` to force stored ownership, while GNU tar
(Linux) uses ``--owner``/``--group``.  Keep both paths here so every stream that
must land on the device as root stays portable.
"""
import sys


def owner_args(uid=None, gid=None):
    """Return tar flags that force numeric owner/group for new archive entries."""
    args = []
    if sys.platform == "darwin":
        if uid is not None:
            args += ["--uid", str(uid)]
        if gid is not None:
            args += ["--gid", str(gid)]
    else:
        if uid is not None:
            args.append(f"--owner={uid}")
        if gid is not None:
            args.append(f"--group={gid}")
    return args


def normalize_args():
    """Return platform-specific flags that keep streamed metadata device-safe.

    GNU tar otherwise stores uname/gname alongside numeric ids and may include
    ACL/SELinux metadata.  The iOS ramdisk only understands the numeric fields,
    so strip those extras on Linux.  macOS bsdtar is already covered by the
    caller's ``--no-xattrs`` and must not receive GNU-only flags.
    """
    if sys.platform == "darwin":
        return []
    return ["--no-acls", "--no-selinux", "--numeric-owner"]
