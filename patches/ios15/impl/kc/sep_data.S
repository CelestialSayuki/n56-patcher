.text
.p2align 2
// Inline instruction templates, NOT a new executable cave. All six controls
// fit at their guarded native sites; previous SEP/RTBuddy payloads stay intact.
.global legacy_media_tag
legacy_media_tag:
    mov w0, #1
.global legacy_media_tag_end
legacy_media_tag_end:

// 19H422 factored migration into a helper. Its caller still releases the
// volume lock and reference after this returns; do not use iOS14's epilogue.
.global skip_media_migration
skip_media_migration:
    mov w0, #0
    ret
.global skip_media_migration_end
skip_media_migration_end:

.global no_locker
no_locker:
    mov w0, #0
    ret
.global no_locker_end
no_locker_end:

// Patched to a PC-relative B at the *native* cookie site, not at this template.
.global skip_volume_cookie
skip_volume_cookie:
    nop
.global skip_volume_cookie_end
skip_volume_cookie_end:
