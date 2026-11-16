.text
.p2align 2
.set SERVICE_COUNT, 5

// iOS 13 SKS initialization, using the iOS 14 AKS and manager layouts.
.globl _sks_init
_sks_init:
    sub sp, sp, #0x40
    stp x22, x21, [sp, #0x10]
    stp x20, x19, [sp, #0x20]
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov x19, x0
    ldr x0, [x19, #0x148]
    cbnz x0, .Linit_return
    adr x0, .Lsks_start_message
    bl .Lsep_log
    mov x0, x19
.globl _sks_enabled
_sks_enabled:
    nop
    tbz w0, #0, .Linit_missing
    mov x0, x19
.globl _sks_manager
_sks_manager:
    nop
    cbz x0, .Linit_missing
    mov x20, x0
    // Register the same callback and reply storage as the native 14 client.
.globl _sks_callback
_sks_callback:
    nop
    nop
    mov x2, x8
    mov x0, x20
    mov x1, x19
    mov w3, #0x12
    add x4, x19, #0x150
    ldr x8, [x20]
    ldr x8, [x8, #0x550]
    blr x8
    cbz x0, .Linit_missing
    mov x21, x0
    ldr x8, [x20]
    ldr x8, [x8, #0x490]
    mov x0, x20
    mov x1, x19
    blr x8
    ldr x8, [x19]
    ldr x8, [x8, #0x378]
    mov x0, x19
    blr x8
    ldr x8, [x0]
    ldr x8, [x8, #0xa0]
    mov x1, x21
    blr x8
    ldr x8, [x21]
    ldr x8, [x8, #0xb0]
    mov x0, x21
    blr x8
    ldr x8, [x19, #0x138]
    cbnz x8, .Linit_output
    adr x0, .Lsks_input_message
    bl .Lsep_log
    ldr x8, [x20]
    ldr x8, [x8, #0x558]
    mov x0, x20
    mov w1, #0
    mov w2, #0x4000
    mov w3, #0x1000
    blr x8
    cbz x0, .Linput_alloc_failed
    mov x22, x0
    ldr x8, [x21]
    ldr x8, [x8, #0x100]
    mov x0, x21
    mov x1, x22
    blr x8
    cbnz w0, .Linput_bind_failed
    str x22, [x19, #0x138]
.Linit_output:
    ldr x8, [x19, #0x140]
    cbnz x8, .Linit_finish
    adr x0, .Lsks_output_message
    bl .Lsep_log
    ldr x8, [x20]
    ldr x8, [x8, #0x558]
    mov x0, x20
    mov w1, #0
    mov w2, #0x4000
    mov w3, #0x1000
    blr x8
    cbz x0, .Loutput_alloc_failed
    mov x20, x0
    ldr x8, [x21]
    ldr x8, [x8, #0x108]
    mov x0, x21
    mov x1, x20
    blr x8
    cbnz w0, .Loutput_bind_failed
    str x20, [x19, #0x140]
.Linit_finish:
    str x21, [x19, #0x148]
    adr x0, .Lsks_protocol_message
    bl .Lsep_log
    mov x0, x19
.globl _sks_protocol
_sks_protocol:
    nop
    adr x0, .Lsks_ready_message
    bl .Lsep_log
.Linit_missing:
    ldr x0, [x19, #0x148]
.Linit_return:
    ldp x29, x30, [sp, #0x30]
    ldp x20, x19, [sp, #0x20]
    ldp x22, x21, [sp, #0x10]
    add sp, sp, #0x40
    ret
.Linput_alloc_failed:
.globl _sks_input_alloc_failed
_sks_input_alloc_failed:
    nop
.Linput_bind_failed:
    mov x1, x0
    mov x0, x22
.globl _sks_input_bind_failed
_sks_input_bind_failed:
    nop
.Loutput_alloc_failed:
.globl _sks_output_alloc_failed
_sks_output_alloc_failed:
    nop
.Loutput_bind_failed:
    mov x0, x20
.globl _sks_output_bind_failed
_sks_output_bind_failed:
    nop

// N56 wakes on a mailbox interrupt. iOS 14 moved this wait into the manager
// and started requiring a decoded 0x0f/0x15 control reply.
.p2align 2
.globl _sep_legacy_wake
_sep_legacy_wake:
    sub sp, sp, #0x40
    stp x22, x21, [sp, #0x10]
    stp x20, x19, [sp, #0x20]
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov x19, x0
    ldr x21, [x0, #0x88]
    add x20, x0, #0x168
    mov w22, #0
    adr x0, .Lwake_start_message
    bl .Lsep_log
.Lwake_wait:
    stlrb wzr, [x20]
    mov x0, x20
    mov w1, #0
    mov w2, #1
    mov w3, #0x4240
    movk w3, #0xf, lsl #16
.globl _sep_assert_wait
_sep_assert_wait:
    nop
    mov w19, #2
.Lwake_write:
    ldr x9, [x21, #0xa8]
    ldr w8, [x9, #0x1008]
    tbnz w8, #16, .Lwake_next
    str xzr, [x9, #0x1010]
.Lwake_next:
    subs w19, w19, #1
    b.ne .Lwake_write
    mov x0, #0
.globl _sep_thread_block
_sep_thread_block:
    nop
    ldarb w8, [x20]
    cbnz w8, .Lwake_success
    add w22, w22, #1
    cmp w22, #1000
    b.lo .Lwake_wait
    mov w0, #0x2d6
    movk w0, #0xe000, lsl #16
    b .Lwake_return
.Lwake_success:
    mov w0, #0
.Lwake_return:
    mov x19, x0
    stp x19, x22, [sp]
    adr x0, .Lwake_return_message
    bl .Lsep_log
    mov x0, x19
    ldp x29, x30, [sp, #0x30]
    ldp x20, x19, [sp, #0x20]
    ldp x22, x21, [sp, #0x10]
    add sp, sp, #0x40
    ret

// The transport invokes this manager callback from its native IRQ filter.
.p2align 2
.globl _sep_legacy_irq
_sep_legacy_irq:
    mov x19, x0
    ldr w8, [x0, #0xcc]
    cmp w8, #8
    b.ne .Lirq_resume
    add x0, x0, #0x168
    mov w9, #1
.Lirq_set:
    ldaxrb w8, [x0]
    cbnz w8, .Lirq_set_done
    stlxrb w8, w9, [x0]
    cbnz w8, .Lirq_set
    mov w1, #0
    mov w2, #0
.globl _sep_thread_wakeup
_sep_thread_wakeup:
    nop
    b .Lirq_resume
.Lirq_set_done:
    clrex
.Lirq_resume:
    mov x0, x19
.globl _sep_irq_resume
_sep_irq_resume:
    nop

// Publish the fixed SEP 12 services required by the native 14 clients.
.p2align 2
.globl _sep_legacy_services
_sep_legacy_services:
    stp x20, x21, [sp, #-0x20]!
    stp x29, x30, [sp, #0x10]
    add x29, sp, #0x10
    ldr w8, [x19, #0x17c]
    adr x20, .Lservices_4k
    adr x9, .Lservices_16k
    cmp w8, #0
    csel x20, x20, x9, eq
// 条目数默认不含末尾的 sbio；功能 touchid（kc.touchid）把这条改成 SERVICE_COUNT + 1。
.globl _sep_service_count
_sep_service_count:
    add x21, x20, #(SERVICE_COUNT * 12)
.Lservice_publish:
    mov x0, x20
    mov x1, x19
.globl _sep_service_factory
_sep_service_factory:
    nop
    add x20, x20, #12
    cmp x20, x21
    b.ne .Lservice_publish
    ldp x29, x30, [sp, #0x10]
    ldp x20, x21, [sp], #0x20
    str x23, [sp]
.globl _sep_services_resume
_sep_services_resume:
    nop

.p2align 2
.globl _services_4k
.Lservices_4k:
_services_4k:
    .long 0x6c6f6720
    .byte 1, 0, 0, 0, 4
    .space 3
    .long 0x61727472
    .byte 3, 4, 4, 4, 4
    .space 3
    .long 0x61727473
    .byte 2, 4, 4, 4, 4
    .space 3
    // The credential app uses endpoint 10 with 0x1000-byte buffers.
    .long 0x73637264
    .byte 10, 1, 1, 1, 1
    .space 3
    // AppleSSE: endpoint 12, one 0x1000-byte buffer per direction.
    .long 0x73736520
    .byte 12, 1, 1, 1, 1
    .space 3
    // Touch ID（AppleMesaSEPDriver，"sep-endpoint,sbio"）：12/13 断言 endpoint == 8，
    // 缓冲 0x4000 / 0x4b000 字节，两个方向各允许 0..0x4b 页。仅在 touchid 功能下计入条目数。
    .long 0x7362696f
    .byte 8, 0, 0x4b, 0, 0x4b
    .space 3
.globl _services_16k
.Lservices_16k:
_services_16k:
    .long 0x6c6f6720
    .byte 1, 0, 0, 0, 1
    .space 3
    .long 0x61727472
    .byte 3, 1, 1, 1, 1
    .space 3
    .long 0x61727473
    .byte 2, 1, 1, 1, 1
    .space 3
    .long 0x73637264
    .byte 10, 1, 1, 1, 1
    .space 3
    .long 0x73736520
    .byte 12, 1, 1, 1, 1
    .space 3
    .long 0x7362696f
    .byte 8, 0, 0x13, 0, 0x13
    .space 3

// Logs run in the calling thread; the IRQ hook remains free of console I/O.
.p2align 2
.Lsep_log:
.globl _sep_stage_log
_sep_stage_log:
    nop
.Lsks_start_message:
    .asciz "SKS fixed init\n"
.Lsks_input_message:
    .asciz "SKS bind input\n"
.Lsks_output_message:
    .asciz "SKS bind output\n"
.Lsks_protocol_message:
    .asciz "SKS protocol begin\n"
.Lsks_ready_message:
    .asciz "SKS protocol returned\n"
.Lwake_start_message:
    .asciz "SEP legacy wake begin\n"
.Lwake_return_message:
    .asciz "SEP legacy wake result=%#lx retries=%lu\n"
