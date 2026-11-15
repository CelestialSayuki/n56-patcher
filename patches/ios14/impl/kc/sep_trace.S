.text
.p2align 2

// 诊断：文件密钥的 v1/v2 入口都先进这里，再调用 14.8 内核保留的 v0 编码器；v0 返回非 0 时
// 打印操作号、返回码和请求参数值（w3|w4<<32、w6|w7<<32）。加密 Data14 上 SKS 操作 9 的
// file_op 返回 -11，再被翻译成 AKS unwrap_key 的 0xe00002c2，用这些值判断 iOS 14 填了什么
// iOS 12 SEP 不认识的东西。v0 最多读 8 个栈参数，原样复制。
// 这段代码放在已废弃的原版 v1 file_op 编码器函数体里（入口第一条已改成跳进 v0 桥），
// 不占 __TEXT_EXEC 的补丁空间。
.globl _trace_file_op
_trace_file_op:
    mov w15, #0
    b .Ltrace
.globl _trace_file_wrap
_trace_file_wrap:
    mov w15, #1
    b .Ltrace
.globl _trace_file_unwrap
_trace_file_unwrap:
    mov w15, #2
.Ltrace:
    sub sp, sp, #0x70
    stp x29, x30, [sp, #0x60]
    add x29, sp, #0x60
    str x15, [sp, #0x48]
    mov w11, w3
    bfi x11, x4, #32, #32
    mov w12, w6
    bfi x12, x7, #32, #32
    stp x11, x12, [sp, #0x50]
    ldp x9, x10, [sp, #0x70]
    stp x9, x10, [sp]
    ldp x9, x10, [sp, #0x80]
    stp x9, x10, [sp, #0x10]
    ldp x9, x10, [sp, #0x90]
    stp x9, x10, [sp, #0x20]
    ldp x9, x10, [sp, #0xa0]
    stp x9, x10, [sp, #0x30]
    adr x16, .Lv0_table
    add x16, x16, x15, lsl #2
    blr x16
    cbz w0, 1f
    str x0, [sp, #0x40]
    ldr x9, [sp, #0x48]
    and x10, x0, #0xffffffff
    stp x9, x10, [sp]
    ldp x9, x10, [sp, #0x50]
    stp x9, x10, [sp, #0x10]
    adr x0, .Ltrace_message
.globl _call_log
_call_log:
    nop
    ldr x0, [sp, #0x40]
1:
    ldp x29, x30, [sp, #0x60]
    add sp, sp, #0x70
    ret
// 跳转表：每项一条 b 指令，由 sep_rpc.py 填成对应 v0 编码器（blr 进来，v0 直接返回到上面）
.globl _v0_table
_v0_table:
.Lv0_table:
    nop
    nop
    nop
.Ltrace_message:
    .asciz "sks%lu ret=%#lx w3w4=%#lx w6w7=%#lx\n"
.p2align 2
