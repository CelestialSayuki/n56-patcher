// GenericTransfer is shared. Only SBIO instances enter Mesa's legacy receive ABI.
// Other clients execute the displaced native SUB and resume the untouched body.
.text
.p2align 2
.globl _mesa_receive_dispatch
_mesa_receive_dispatch:
    ldr w8, [x0, #0x1c]
    mov w9, #0x696f
    movk w9, #0x7362, lsl #16
    cmp w8, w9
    b.ne .Lnative
    b _mesa_receive
.Lnative:
    sub sp, sp, #0x80
    b _mesa_receive_resume
