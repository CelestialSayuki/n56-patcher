# Pinned upstream / native host port

- Repository: https://github.com/palera1n/PongoOS
- Branch at baseline audit: `iOS15`
- Commit: `e98323f8a09abd80fc4cbcd74dee023b91a1ec22`
- Download: commit-addressed GitHub codeload tarball (no branch/latest dependency).
- Archive SHA-256: `736e5f5a0b90d48934eee813b6c401764ff16fe6ad99aba4bc1240d15a9cecbb`
- `vendor/` contains 29 **unmodified** required sources/headers/license. Every file
  hash is in `upstream-manifest.json`, checked before the host adaptation is built.
  `main.c`, `kpf.h`, and `vfs.c` were byte-compared to the fixed snapshot already
  in `build/ios15-kpf-upstream/palera1n/`.
- License: upstream MIT; full license notices are retained, including the source
  headers. `vendor/LICENSE.md` also documents third-party parts of full PongoOS;
  those drivers are not compiled here.

## Deliberate adaptations

`scripts/prepare.py` emits host-specific C under `.build/`, using exact,
fail-on-drift transformations. It does not modify vendor or an older KPF tree.

1. Keep upstream semantic matching, version/platform checks, AMFI/trustcache,
   dyld/VFS, VM, Mach ports/traps, sandbox, APFS permissions, rootvp auth.
2. Disable ARM JIT at compile time; use bounded native-C matching. ARM shellcode
   and legacy JIT template labels are assembled only into read-only data blobs.
   The mapper has no executable permissions; JIT allocation calls panic.
3. Replace the upstream zero-pattern shellcode search with explicit protected
   prelink-padding allocation from both input KCs and existing declarations.
4. Explicit generic-profile exclusions: bindfs, overlay, ramdisk, md0oncores,
   launchd redirection, snapshot selection, force-revert. These are installer/boot
   components, not missing required matches disguised as optional. The upstream
   `KPF_TEST` force-revert guard bypass is corrected to respect runtime flags.
5. Keep `if (!have_ssv)` around **required** `apfs_patch_rename`; a detected SSV
   never registers it. Keep root_livefs's upstream `#if 0`, with a separately owned
   `kc.ssv_livefs` leaf for the exact J96 guard.
6. `DEV_BUILD` keeps upstream invariant checks, but does not override the
   production rootful flag guard for `apfs_vfsop_mount` (root remount RW). The
   matcher remains required when registered under rootful; this rootless profile
   never registers it and its report records `root_remount_rw_patch=false`.
   No fakefs/installation flags are selected.

The bounded interpreter reads live candidate bytes rather than an ARM JIT or
rolling prefetch, so a modifying callback cannot leave stale preread evidence.
Original required booleans, alternative matching, getters and finish panics are
retained; additional Python semantic-group checks strengthen the final proof.

This is **not** a whole PongoOS/palera1n build, bootloader, or phone-side installer.
