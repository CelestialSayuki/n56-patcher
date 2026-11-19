.text
.p2align 2
// XNU21 -> N56 v0. Darwin packs stack u32s; sN below is caller_sp+N.
// Modern-only inputs MUST be checked before any v0/SEP call. Empty byte
// strings may have a nonnull pointer: length is u32, pointer is not read.
// persona_uuid/volume_uuid attributes are absent for ordinary BAG1 maps.
// They cannot be represented in v0; neither can v2's additional crypto blobs.
.macro empty_blob pointer, length
    cbz \length, 1f
    cbz \pointer, rpc_bad_argument
    b rpc_unsupported
1:
.endm
.global media_create_v1
media_create_v1:
    // Native create callers use selector=-1, policy=0 (65e913c/65e9140).
    // Other selections/policies have no field in the native12 SKS49 request.
    cmn w3, #1
    b.ne rpc_unsupported
    cbnz w4, rpc_unsupported
    sub sp, sp, #0x20
    stp x29, x30, [sp, #0x10]
    add x29, sp, #0x10
    mov x3, x5
    mov x4, x6
    mov x5, x7
    ldp x6, x7, [sp, #0x20]
    ldp x8, x9, [sp, #0x30]
    stp x8, x9, [sp]
.global call_media_create_v1
call_media_create_v1:
    nop
    ldp x29, x30, [sp, #0x10]
    add sp, sp, #0x20
    ret

.global media_unwrap_v1
media_unwrap_v1:
    // w5=-1 is the native legacy/default selector (65e9208 -> 65effdc).
    // w6 is the optional on-disk policy from callback flag bit5; reject it.
    cmn w5, #1
    b.ne rpc_unsupported
    cbnz w6, rpc_unsupported
    sub sp, sp, #0x20
    stp x29, x30, [sp, #0x10]
    add x29, sp, #0x10
    mov x5, x7
    ldp x6, x7, [sp, #0x20]
    ldp x8, x9, [sp, #0x30]
    stp x8, x9, [sp]
.global call_media_unwrap_v1
call_media_unwrap_v1:
    nop
    ldp x29, x30, [sp, #0x10]
    add sp, sp, #0x20
    ret

.global file_op_v1
file_op_v1:
    empty_blob x4, w5                 // volume/persona attributes
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov w4, w6
    mov x5, x7
    ldp w6, w7, [sp, #0x40]
    ldp x8, x9, [sp, #0x48]
    ldp x10, x11, [sp, #0x58]
    ldr x12, [sp, #0x68]
    stp x8, x9, [sp]
    stp x10, x11, [sp, #0x10]
    str x12, [sp, #0x20]
.global call_file_op_v1
call_file_op_v1:
    nop
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret

.global file_wrap_v1
file_wrap_v1:
    empty_blob x3, w4                 // volume/persona attributes
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov w3, w5
    mov w4, w6
    mov w5, w7
    ldr w6, [sp, #0x40]
    ldr x7, [sp, #0x48]
    ldp x8, x9, [sp, #0x50] // packed w at s16/s20, pointer at s24
    ldr w10, [sp, #0x60]
    ldp x11, x12, [sp, #0x68]
    ldr x13, [sp, #0x78]
    stp x8, x9, [sp]
    str w10, [sp, #0x10]
    stp x11, x12, [sp, #0x18]
    str x13, [sp, #0x28]
.global call_file_wrap_v1
call_file_wrap_v1:
    nop
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret

.global file_unwrap_v1
file_unwrap_v1:
    empty_blob x4, w5                 // volume/persona attributes
    sub sp, sp, #0x50
    stp x29, x30, [sp, #0x40]
    add x29, sp, #0x40
    mov w4, w6
    mov w5, w7
    ldr x6, [sp, #0x50]
    ldr w7, [sp, #0x58]
    ldp x8, x9, [sp, #0x60]
    ldp x10, x11, [sp, #0x70]
    ldp x12, x13, [sp, #0x80]
    ldp x14, x15, [sp, #0x90]
    stp x8, x9, [sp]
    stp x10, x11, [sp, #0x10]
    stp x12, x13, [sp, #0x20]
    stp x14, x15, [sp, #0x30]
.global call_file_unwrap_v1
call_file_unwrap_v1:
    nop
    ldp x29, x30, [sp, #0x40]
    add sp, sp, #0x50
    ret

.global file_op_v2
file_op_v2:
    empty_blob x4, w5                 // volume/persona attributes
    ldr x8, [sp, #8]                  // extra input blob1 s8 / u32 s16
    ldr w9, [sp, #16]
    empty_blob x8, w9
    ldr x8, [sp, #24]                 // extra input blob2 s24 / u32 s32
    ldr w9, [sp, #32]
    empty_blob x8, w9
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov w4, w6
    mov x5, x7
    ldr w6, [sp, #0x40]
    ldr w7, [sp, #0x64]
    ldp x8, x9, [sp, #0x68]
    ldp x10, x11, [sp, #0x78]
    ldr x12, [sp, #0x88] // caller s72, not the out-of-bounds old s88
    stp x8, x9, [sp]
    stp x10, x11, [sp, #0x10]
    str x12, [sp, #0x20]
.global call_file_op_v2
call_file_op_v2:
    nop
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret

.global file_wrap_v2
file_wrap_v2:
    empty_blob x3, w4                 // volume/persona attributes
    ldr x8, [sp, #8]                  // extra input blob1 s8 / u32 s16
    ldr w9, [sp, #16]
    empty_blob x8, w9
    ldr x8, [sp, #24]                 // extra input blob2 s24 / u32 s32
    ldr w9, [sp, #32]
    empty_blob x8, w9
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov w3, w5
    mov w4, w6
    mov w5, w7
    ldr w6, [sp, #0x40]
    ldr x7, [sp, #0x68]
    ldr w8, [sp, #0x70]
    ldr w9, [sp, #0x74]
    ldr x10, [sp, #0x78]
    ldr w11, [sp, #0x80]
    // SKS15 rewrap: match 13/14 flags (0x1c -> 0xc, 0 stays 0).
    and w11, w11, #0xffffffef
    ldp x12, x13, [sp, #0x88]
    ldr x14, [sp, #0x98]
    stp w8, w9, [sp]
    str x10, [sp, #8]
    str w11, [sp, #0x10]
    stp x12, x13, [sp, #0x18]
    str x14, [sp, #0x28]
.global call_file_wrap_v2
call_file_wrap_v2:
    nop
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret

// SKS16: preserve outputs 1,2,4, plus final result/length parameters.
// Output 3/5 are the additional v2 byte-string pairs, absent from v0.
// Native typed B decoder 660e2ac/660e2e8 for an EMPTY reply preserves the
// caller's existing buffer pointer and writes u32 length=0. Do not zero the
// pointer (would leak a supplied allocation), touch its buffer, or write on
// error. The real caller supplies output3 s64/72 and output5 s96/104.
.global file_unwrap_v2
file_unwrap_v2:
    empty_blob x4, w5                 // volume/persona attributes
    ldr x8, [sp, #16]                 // extra input blob s16 / u32 s24
    ldr w9, [sp, #24]
    empty_blob x8, w9
    // Request flags (v0 field +0x78, caller s8). The native12-compatible v0 body
    // and the verified iOS14 bridge send 0xc; 19H422's newkey caller (65eb9bc)
    // hardcodes 0x1c = 0xc | 0x10. Bit 0x10 is modern-only and unknown to the
    // N56 SEP, which answers -1 (e00002bc). Accept only that exact value and
    // send the legacy one; anything else is refused before any v0/SEP call.
    ldr w10, [sp, #8]
    cmp w10, #0x1c
    b.ne rpc_unsupported
    sub sp, sp, #0x50
    stp x29, x30, [sp, #0x40]
    add x29, sp, #0x40
    mov w4, w6
    mov w5, w7
    ldr x6, [sp, #0x50]
    mov w7, #0xc
    ldp x8, x9, [sp, #0x70]
    ldp x10, x11, [sp, #0x80]
    ldp x12, x13, [sp, #0xa0] // output4 is the wrapped on-disk key
    ldp x14, x15, [sp, #0xc0]
    stp x8, x9, [sp]
    stp x10, x11, [sp, #0x10]
    stp x12, x13, [sp, #0x20]
    stp x14, x15, [sp, #0x30]
.global call_file_unwrap_v2
call_file_unwrap_v2:
    nop
    cbnz w0, 3f
    ldr x8, [sp, #0x98]               // caller s72, output3 length pointer
    cbz x8, 2f
    str wzr, [x8]                    // 4 bytes, not 8; preserve *buffer
2:
    ldr x8, [sp, #0xb8]               // caller s104, output5 length pointer
    cbz x8, 3f
    str wzr, [x8]
3:
    ldp x29, x30, [sp, #0x40]
    add sp, sp, #0x50
    ret

// IOReturn errors, never a forged success. Leaf rejection preserves LR/SP and
// every callee-saved register, without reading any blob or output buffer.
rpc_bad_argument:
    mov w0, #0x2c2
    movk w0, #0xe000, lsl #16
    ret
rpc_unsupported:
    mov w0, #0x2c7
    movk w0, #0xe000, lsl #16
    ret
