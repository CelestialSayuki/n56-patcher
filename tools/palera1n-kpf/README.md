# Intel/offline palera1n XNU21 KPF

Native C matcher + ARM data blobs, pinned to PongoOS `e98323f8`; no USB/SSH/JIT,
no ARM execution and no runtime dependency download. Requires macOS Command Line
Tools (`clang`, `nm`, `make`) and Python 3.9+; no iPhone SDK/full Xcode/Swift/Go.

```sh
make -C tools/palera1n-kpf HOST_ARCH=x86_64 PYTHON=python3
python3 -m patches.ios15.impl.kc.palera1n \
  --stock ipsw/cache/derived/ios15-19H422/j96/kernel.raw \
  --current /path/to/latest-pre-KPF.raw \
  --claims /path/to/existing-patch-report.json \
  --work build/n56-ios15-19H422/palera1n-kpf-final
```

`--claims` is repeatable. The pipeline uses existing `ctx.patch_reports` instead.
Run KPF on stock, allocate against current, then strictly three-way-merge each
byte. A differing same-byte co-write or unallocatable cave is a controlled error.
A different stock hash, aggregate mapping, platform/Darwin, or ambiguous ARV
policy also fails. Current must be the latest **pre-KPF** classic raw KC, not an
already KPF-patched result. Output work paths may not alias either input.

ABI: `apply_profile(ctx, stock, current) -> str(raw_path)`; report is stored in
`ctx.patch_reports['kc.palera1n']`. This feature is opt-in and runs after all iOS15
hardware/audio/legacySEP/RTBuddy/TouchID leaves. `kc.ssv_livefs` runs afterwards.
No common flow/installation/composer or old iOS13/14 tool is changed.
`DEV_BUILD` diagnostics remain enabled, but `apfs_vfsop_mount` root-remount-RW
registration respects the rootful flag. This rootless profile excludes that
matcher from its semantic required groups and rejects any accidental registration;
successful reports record `root_remount_rw_patch=false` and
`ssv_livefs.apfs_vfsop_mount="skipped_by_rootless_policy"`. APFS root mount
permissions (`apfs_patch_mount`) and rootvp authentication stay required.

Outputs include merged `kc.palera1n.raw`, stock-only `kc.palera1n.stock.raw`,
`palera1n-report.json`, per-item `kpf-events.jsonl`, exact delta ranges, protected
cave declarations, and a copy of the native Intel executable. A successful
report sets the install-proof fields only after readback and conflict checks.

Policy revision 2 removes the earlier DEV-only rootless root-RW patch. No real
KC has been rerun for this small fix: existing raw outputs are historical
revision-1 artifacts, not validation of revision 2. The old report is archived
as `palera1n-report.before-rootless-remount-fix.json`; the current report is marked
pending final integration (`required_complete=false`, `output_sha256=null`).
The rebuilt Intel tool is current. The integration agent must generate fresh raw
from stock plus the latest pre-KPF KC before consuming a successful install proof.

Small synthetic tests only (no real KC/package run):

```sh
python3 tools/palera1n-kpf/test_offline.py
clang -arch x86_64 tools/palera1n-kpf/host/paleinfo-user-test.c -o /tmp/paleinfo-test
/tmp/paleinfo-test
```

## User-mode paleinfo ABI (not kerninfo)

The original ABI is in `vendor/include/paleinfo.h`; `include/paleinfo-user.h`
provides `n56_paleinfo_read_fd(fd, &info)` and validation, without opening a device
or writing storage. The caller supplies an FD for the boot-chain ramdisk transport.
The first LE uint32 is the byte offset to a packed 48-byte paleinfo v2:

| offset | type | meaning |
|---:|---|---|
| 0 | uint32 | C magic `'PLSH'` = `0x504c5348` (LE bytes `HSLP`) |
| 4 | uint32 | version 2 |
| 8 | uint64 | **runtime** kernel base |
| 16 | uint64 | **runtime** kernel slide |
| 24 | uint64 | palera1n flags, this profile `0x82` = rootless + SSV |
| 32 | char[16] | NUL-terminated BSD rootdev name |

Upstream appends this structure at the original ramdisk length, stores that
length in byte zero's uint32, and reserves an extra `0x10000` bytes. This generic
KPF does **not** create/install that ramdisk or redirect launchd to `/cores/ploosh`.
The final boot chain must supply runtime base/slide and the chosen rootdev if its
bootstrap consumes paleinfo; the produced JSON is only an unslid template.

`paleinfo.py encode/decode` handles HOST files and refuses `/dev/` paths. Do not
substitute offline `kslide=0` for the actual boot-time values. Reading paleinfo
provides metadata only: it does not provide kernel-RW, a kerninfo syscall, or the
old checkra1n 0.12.4 offsetcache. A bootstrap requiring those old APIs needs a
separate adaptation/provider; no old cache is injected into this KC.

The upstream dyld hook retains `/cores/usr/lib/dyld` lookup with fallback to
`/usr/lib/dyld`. General sandbox/setuid support is preserved; no `/var/jb` tree,
rootless userland, bind mount, overlay, fakefs, or package is installed here.

See `../../docs/conclusions/15.md` for the status and remaining runtime/integration
work, and `UPSTREAM.md` for exact adaptations/licensing.
