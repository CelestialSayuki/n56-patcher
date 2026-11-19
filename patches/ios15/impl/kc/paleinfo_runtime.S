/* ARMv8-A metadata-only AMFI policy call, no kernel read/write API.
 * Unknown selectors execute the displaced native prologue unmodified.
 * Private selector 0x1000 receives a 48-byte user buffer in x2.
 */
.text
.balign 16
paleinfo_entry:
    cmp w1, #1, lsl #12
    b.eq paleinfo_export
paleinfo_native:
    nop /* relocated native first instruction */
paleinfo_resume:
    nop /* direct branch back to native entry+4 */
paleinfo_export:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    mov x20, x2
paleinfo_cred_get:
    nop /* bl kauth_cred_get */
paleinfo_is_root:
    nop /* bl kauth_cred_issuser */
    cbz w0, paleinfo_denied
    adr x8, paleinfo_entry
    ldr x9, paleinfo_unslid_cave
    sub x8, x8, x9
    tst x8, #0x3fff
    b.ne paleinfo_invalid
    ldr x9, paleinfo_unslid_base
    adds x9, x9, x8
    b.cs paleinfo_invalid
    ldr w10, [x9]
    ldr w11, paleinfo_macho_magic
    cmp w10, w11
    b.ne paleinfo_invalid
    ldr x10, paleinfo_magic_version
    str x10, [sp, #32]
    stp x9, x8, [sp, #40]
    ldr x10, paleinfo_flags
    str x10, [sp, #56]
    adr x11, paleinfo_rootdev
    ldp x9, x10, [x11]
    stp x9, x10, [sp, #64]
    add x0, sp, #32
    mov x1, x20
    mov w2, #48
paleinfo_copyout:
    nop /* bl copyout; its actual errno is returned */
    b paleinfo_return
paleinfo_denied:
    mov w0, #1 /* EPERM */
    b paleinfo_return
paleinfo_invalid:
    mov w0, #22 /* EINVAL, never fabricate base/slide */
paleinfo_return:
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret
.balign 8
paleinfo_unslid_cave:
    .quad 0
paleinfo_unslid_base:
    .quad 0xfffffff007004000
paleinfo_magic_version:
    .quad 0x00000002504c5348
paleinfo_flags:
    .quad 0
paleinfo_macho_magic:
    .word 0xfeedfacf
.balign 8
paleinfo_rootdev:
    .zero 16
