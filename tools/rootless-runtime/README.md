# Basic rootless runtime identity guard

A tiny ordinary arm64/ARMv8-A iOS12-compatible executable, linked only to native
libSystem using shared Darwin POSIX headers. It runs on the iOS15 system, not the
Intel host. No full iPhone SDK, kernel-RW, raw-device access or paleinfo is invented.

`patches.ios15.impl.rootfs.rootless_runtime.prepare(ctx)` builds/signs once and
reuses the content-bound result. Device path:
`/var/jb/usr/libexec/n56-rootless-runtime`.

```
n56-rootless-runtime verify --binding FILE --package FILE
n56-rootless-runtime start  --binding FILE --package FILE
```

Stage0 runs from System15 and first updates Data15 with
`/sbin/mount -u -o suid /private/var`. Both runtime modes then check actual
XNU21.6, root-owned metadata, distinct System/Data UUIDs via getattrlist, BSD
slices/mountpoints via statfs, System ro, Data rw/suid/nodev, the `/var/jb`
target on that same Data volume, and no root snapshots via fs_snapshot_list.
Any remaining `nosuid` is a hard failure before a Data-hosted interpreter runs.
`start` repeats the check; the explicit bootstrap job owns package configuration
and scoped daemon starts.

Binding fields: `build=19H422`, `layout=data-private-preboot-v1`, `system_slice`,
`data_slice`, `system_uuid`, `data_uuid`, `runtime_root`, `package_fingerprint`,
`amfi_policy=palera1n-trustcache-bypass`. Package file is one fingerprint line.
Installer metadata is built from verified boot artifacts and actual APFS facts,
not a null UUID template or another approval prompt.

The pinned PongoOS trustcache callback makes AMFI believe every hash is trusted;
this is an explicit KPF bypass policy, **not a dynamic-TC service**. Thus basic
bootstrap does not depend on a missing paleinfo FD/KRW provider. Consumers that
actually require runtime kernel base/slide/KRW remain unsupported until supplied;
no offline slide=0 is substituted. Initial helper/package signed inputs are still
verified and included in the actual combined TC before deployment.

The signed ARM helper is never executed on the host. `parser-test.c` is a native
Intel parser-only regression; it invokes none of the filesystem/device APIs.
JSMN is pinned with its complete MIT notice and digest in `UPSTREAM.json`.
