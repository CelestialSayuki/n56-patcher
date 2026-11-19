// Explicit legacy-wire entry in the shared GenericTransfer transact ABI.
// Untagged modern requests (including Mesa's existing imports) remain native.
.text
.p2align 2
.globl _sep_transfer_transact_dispatch
_sep_transfer_transact_dispatch:
    cbz x0, .Lnative
    ldr w8, [x0, #0x1c]
    mov w9, #0x696f
    movk w9, #0x7362, lsl #16
    cmp w8, w9
    b.ne .Lnative
    tbz w1, #31, .Lnative
    and w1, w1, #0x7fffffff
.globl _sep_transfer_runtime_jump
_sep_transfer_runtime_jump:
    nop
.Lnative:
    sub sp, sp, #0xa0
.globl _sep_transfer_transact_resume
_sep_transfer_transact_resume:
    nop
