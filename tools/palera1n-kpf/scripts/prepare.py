#!/usr/bin/env python3
"""Reproducible, hash-guarded host-only adaptation of the pinned upstream.

No required patch becomes optional. Installer/boot-hook components are explicitly
excluded from the generic profile, rather than run against a nonexistent ramdisk.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'vendor'
OUT = ROOT / '.build'


def replace_once(s, old, new):
    if s.count(old) != 1:
        raise ValueError('pinned upstream drift: ' + old[:90])
    return s.replace(old, new, 1)


def main():
    manifest = json.loads((ROOT / 'upstream-manifest.json').read_text())
    for name, digest in manifest['files'].items():
        if hashlib.sha256((VENDOR / name).read_bytes()).hexdigest() != digest:
            raise ValueError('upstream hash mismatch: ' + name)
    OUT.mkdir(exist_ok=True)
    s = (VENDOR / 'checkra1n/kpf/main.c').read_text()
    s = replace_once(s, '#include "kpf.h"', '#include "kpf.h"\n#include "offline.h"')
    # These components belong to the palera1n jbinit boot/installation chain.
    for name in ('bindfs', 'overlay', 'ramdisk'):
        s = replace_once(s, '        &kpf_' + name + ',\n', '')
    # DEV_BUILD must keep diagnostics, not enable root remount RW on rootless.
    # Restore upstream production's rootful guard; the existing rootful-only
    # finish panic stays intact. This patch remains required when registered.
    s = replace_once(s, '''        apfs_vfsop_mount_string_match
#ifndef DEV_BUILD
       && palera1n_flags & palerain_option_rootful // this patch is not required on rootless
#endif''', '''        apfs_vfsop_mount_string_match
       && (palera1n_flags & palerain_option_rootful) // no root RW on rootless''')
    # KPF_TEST bypasses runtime guards for upstream's broad corpus tests. Restore
    # the real force-revert guard in our production host port (SSV never reverts).
    s = replace_once(s, '''#if !defined(KPF_TEST)
    (palera1n_flags & palerain_option_ssv) == 0
    && (palera1n_flags & palerain_option_force_revert)
    && (palera1n_flags & palerain_option_rootful) &&
#endif''', '''    (palera1n_flags & palerain_option_ssv) == 0
    && (palera1n_flags & palerain_option_force_revert)
    && (palera1n_flags & palerain_option_rootful) &&''')
    s = replace_once(s, '''    if (is_ssv_required)
        palera1n_flags |= palerain_option_ssv;''', '''    n56_audit_policy(is_ssv_required, livefs_string_match != NULL,
                     optional_arv_strings_match != NULL);
    if (is_ssv_required)
        palera1n_flags |= palerain_option_ssv;''')
    # This host profile is XNU21/iOS15 only. Optional ARV needs a real DT policy;
    # failing is safer than silently interpreting KPF_TEST's missing DT as false.
    s = replace_once(s, '    kpf_kernel_version_init(text_const_range);', '''    kpf_kernel_version_init(text_const_range);
    if (gKernelVersion.darwinMajor != 21 || xnu_platform() != PLATFORM_IOS)
        panic("n56 offline profile requires XNU21 / PLATFORM_IOS");''')
    start = s.index('    uint64_t matches[count];', s.index('static void kpf_find_shellcode_area('))
    end = s.index('\n}', start)
    s = s[:start] + '''    (void)xnu_text_exec_patchset;
    shellcode_area = n56_select_shellcode(count);
    if (!shellcode_area) panic("Missing patch: shellcode_area (no protected cave)");
''' + s[end:]
    # No /cores mount or execve hook: main thread owns SSV/livefs/installation.
    s = replace_once(s, '''    if(apfs_vfsop_mount_string_match)
    {
        kpf_md0oncores_patch(xnu_text_exec_patchset);
    }''', '    /* md0oncores: excluded by generic offline profile. */')
    s = replace_once(s, '''    if(apfs_vfsop_mount_string_match)
    {
        if (!mdevremoveall)''', '''    if(false) /* md0oncores / jbinit hook excluded, not optionalized. */
    {
        if (!mdevremoveall)''')
    s = replace_once(s, '    if(!(palera1n_flags & palerain_option_ssv)) // Only use underlying fs on union mounts',
                     '    if(false) // Snapshot selection belongs to installation, not generic KPF')
    s = replace_once(s, '    snprintf(launchdString, sizeof("/sbin/launchd"), "/cores/ploosh");',
                     '    /* Preserve /sbin/launchd: no jbinit payload has been installed. */')
    # Keep module_entry for host API, without an overlay command dependency.
    s = replace_once(s, '    command_register("overlay", "loads an overlay disk image", kpf_overlay_cmd);', '')
    s = replace_once(s, '    tick_1 = get_ticks();', '    n56_audit_finish();\n    tick_1 = get_ticks();')
    (OUT / 'kpf-main.c').write_text(s)

    s = (VENDOR / 'src/drivers/xnu/xnu.c').read_text()
    s = replace_once(s, '#include <pongo.h>', '#include <pongo.h>\n#include "offline.h"')
    # Eliminate ARM JIT generation at compile time, on *every* host architecture.
    start = s.index('void xnu_pf_emit(xnu_pf_patchset_t* patchset)')
    end = s.index('\nvoid xnu_pf_apply_8', start)
    s = s[:start] + 'void xnu_pf_emit(xnu_pf_patchset_t* patchset) { (void)patchset; }\n' + s[end:]
    # Remove rolling prereads (they see stale bytes after a modifying callback)
    # and prevent pattern reads crossing the current matching range.
    start = s.index('void xnu_pf_apply_8')
    end = s.index('\nvoid xnu_pf_patchset_destroy', start)
    s = s[:start] + r'''
void xnu_pf_apply(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset) {
    if (!range || patchset->jit_matcher) panic("offline matcher: bad range / JIT");
    unsigned bits = patchset->accesstype;
    if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
        panic("offline matcher: bad granule");
    uint64_t step = bits / 8;
    for (uint64_t offset = 0; offset + step <= range->size; offset += step) {
        uint8_t *stream = (uint8_t *)range->cacheable_base + offset;
        for (xnu_pf_patch_t *patch = patchset->patch_head; patch; patch = patch->next_patch) {
            if (!patch->should_match) continue;
            uint64_t need = step;
            if (patch->pf_match == (void *)xnu_pf_maskmatch_match)
                need = (uint64_t)((struct xnu_pf_maskmatch *)patch)->pair_count * step;
            if (need > range->size - offset) continue;
            patch->pf_match(patch, patchset->accesstype, stream, stream);
        }
    }
    if (patchset->is_required) {
        for (xnu_pf_patch_t *patch = patchset->patch_head; patch; patch = patch->next_patch) {
            if (patch->is_required && !patch->has_fired)
                panic("Missing patch: %s", patch->name);
        }
    }
}
''' + s[end:]
    # Both maskmatch and pointer-to-data callbacks get exact successful sites.
    old = 'patch->patch.has_fired = true;'
    assert s.count(old) == 2
    s = s.replace(old, old + '\n            n56_audit_match((xnu_pf_patch_t *)patch, cacheable_stream);')
    s = replace_once(s, '        free(o_patch);', '        n56_audit_result(o_patch);\n        free(o_patch);')
    # Bounds for pointer-to-data strings, in addition to the pointer granule.
    s = replace_once(s, 'pointer < (patch->range->va + patch->range->size)',
                     'patch->datasz <= patch->range->size && pointer - patch->range->va <= patch->range->size - patch->datasz')
    # JIT emitter pointers are never used by the interpreter. Nulling them also
    # drops the dead ARM JIT emitter imports from the native executable.
    s = replace_once(s, 'mm->patch.pf_emit = (void*)xnu_pf_maskmatch_emit;',
                     'mm->patch.pf_emit = NULL;')
    s = replace_once(s, 'mm->patch.pf_emit = (void*)xnu_pf_ptr_to_data_emit;',
                     'mm->patch.pf_emit = NULL;')
    (OUT / 'xnu.c').write_text(s)


if __name__ == '__main__':
    main()
