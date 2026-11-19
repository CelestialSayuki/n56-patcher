// iOS 15.8.8 / 19H422 J96. Fields and continuations verified offline.
// Preserve the iOS 14 functional bridge; ASP tracing is deliberately not
// transplanted because it would modify another kext (AppleStorageProcessor).
.text
.globl _legacy_map, _alloc_endpoints, _start_endpoint, _enabled_map_low, _enabled_map_high, _power_change, _bad_map
_legacy_map:
    sub sp, sp, #0x50
    stp x24, x23, [sp, #0x10]
    stp x22, x21, [sp, #0x20]
    stp x20, x19, [sp, #0x30]
    stp x29, x30, [sp, #0x40]
    add x29, sp, #0x40
    mov x19, x0
    mov x24, x1
    ldr x0, [x0, #0x70]
    ldr w8, [x0, #0x148]
    cmp w8, #5
    b.ne .Lbad
    ldrb w8, [x19, #0x101]
    cbnz w8, .Lwarm_map
    tbz w1, #0, .Lbad
    and x21, x1, #0xfffffffffffff
    clz x8, x21
    mov w9, #64
    sub w1, w9, w8
_alloc_endpoints:
    nop
    lsr x21, x21, #1
    mov w20, #1
    cbz x21, .Lcomplete
.Lendpoint:
    tbz x21, #0, .Lnext
    ldr x0, [x19, #0x70]
    mov x1, x20
_start_endpoint:
    nop
.Lnext:
    add w20, w20, #1
    lsr x21, x21, #1
    cbnz x21, .Lendpoint
.Lcomplete:
    mov w8, #1
    strb w8, [x19, #0x101]
    mov x21, #1
    b .Lstart_ans
.Lwarm_map:
    mov x0, x19
    mov w1, #0
_enabled_map_low:
    nop
    mov w21, w0
    mov x0, x19
    mov w1, #32
_enabled_map_high:
    nop
    bfi x21, x0, #32, #20
    orr x21, x21, #1
    tbz x24, #6, .Lstart_ans
    orr x21, x21, #0x40
.Lstart_ans:
    // The old firmware needs endpoint 6 started after every HELLO/map,
    // including wake-up when the existing endpoint objects are reused.
    tbz x24, #6, .Lmap_ack
    mov x8, #2
    movk x8, #6, lsl #32
    movk x8, #0x50, lsl #48
    str x8, [sp, #8]
    ldr x8, [x19]
    ldr x8, [x8, #0xe8]
    mov x0, x19
    add x1, sp, #8
    mov x2, #0
    mov w3, #1
    blr x8
.Lmap_ack:
    // iOS 13 returns the enabled 52-bit endpoint map on resume.
    orr x8, x21, #0x80000000000000
    str x8, [sp, #8]
    ldr x8, [x19]
    ldr x8, [x8, #0xe8]
    mov x0, x19
    add x1, sp, #8
    mov x2, #0
    mov w3, #1
    blr x8
    cbnz w0, .Lreturn
    ldr x0, [x19, #0x70]
    mov w1, #6
    // 19H422 RTBuddy state setter is virtual, slot +0x5c0.
    ldr x8, [x0]
    ldr x8, [x8, #0x5c0]
    blr x8
    ldr w8, [x19, #0x104]
    cbz w8, .Lsuccess
    cmp w8, #1
    cset w1, eq
    mov x0, x19
_power_change:
    nop
    b .Lreturn
.Lsuccess:
    mov w0, #0
.Lreturn:
    ldp x29, x30, [sp, #0x40]
    ldp x20, x19, [sp, #0x30]
    ldp x22, x21, [sp, #0x20]
    ldp x24, x23, [sp, #0x10]
    add sp, sp, #0x50
    ret
.Lbad:
    mov x0, x19
_bad_map:
    nop

.globl _legacy_endpoint_dispatch, _dispatch_resume, _dispatch_aux, _dispatch_analytics, _dispatch_generic
_legacy_endpoint_dispatch:
    // Keep builtins 0..4, aux 31 and analytics 32; endpoint 6 is ANS user 1.
    // The verified 15 prologue saves the endpoint in w22 (14 used w20).
    cmp w22, #31
    b.eq .Laux
    cmp w22, #32
    b.eq .Lanalytics
    cmp w22, #4
    b.hi .Lgeneric
    cmp w1, #11
_dispatch_resume:
    nop
.Laux:
_dispatch_aux:
    nop
.Lanalytics:
_dispatch_analytics:
    nop
.Lgeneric:
_dispatch_generic:
    nop

