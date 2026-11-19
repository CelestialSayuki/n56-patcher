.text
.p2align 2
// SKS61 v1 adds a cookie input pair, absent from the genuine N56 receiver.
// Empty pair has v0 semantics. Nonempty input is NOT discarded or fabricated.
.global sks61_empty_v1
sks61_empty_v1:
    cbnz x4, sks61_unsupported
    cbnz w5, sks61_unsupported
    mov x4, x6
    mov x5, x7
.global sks61_v0_call
sks61_v0_call:
    nop // patched to B (tail call), not BL; original LR/SP/status are preserved
sks61_unsupported:
    mov w0, #0x2c7
    movk w0, #0xe000, lsl #16
    ret
.p2align 2
.ascii "N56-SKS61-EMPTY-V0\0"
.p2align 2
