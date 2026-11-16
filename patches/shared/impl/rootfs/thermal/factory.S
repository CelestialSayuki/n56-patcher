// Continue through the original factory after recognizing N56.
.text
.p2align 2
.globl _n56_create_product
_n56_create_product:
    stp x20, x19, [sp, #-0x20]!
    stp x29, x30, [sp, #0x10]
    add x29, sp, #0x10
    mov x19, x0
    str x2, [x0, #8]
    ldr w8, [x0, #0x10]
    mov w9, #0x27ac
    movk w9, #4, lsl #16
    cmp w8, w9
    b.ne 1f
    adrp x9, _n56_class_reference@PAGE
    add x9, x9, _n56_class_reference@PAGEOFF
    b _n56_factory_create
1:
    b _n56_factory_resume
