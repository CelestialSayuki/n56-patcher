.text
.p2align 2

// Keep the v0 key fields and outputs; omit the v2 attribute buffers.
// v2 相对 v1 在栈参数里插入了新的“指针+长度”对，后面的参数整体后移；对照 iOS 13 已验证的
// v1→v0 桥和 14/13 两边的调用方逐个核对过（2026-11-15，boot102 参数日志 + 静态对照）。
.globl _file_op_v2
_file_op_v2:
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov x4, x6
    mov x5, x7
    ldr w6, [sp, #0x40]
    ldr w7, [sp, #0x64]
    ldp x8, x9, [sp, #0x68]
    ldp x10, x11, [sp, #0x78]
    ldr x12, [sp, #0x88]              // v2 s72（= v1 s40 / iOS 13 的 &[x29-0x5c]）；原先读 s88 是越界垃圾
    stp x8, x9, [sp]
    stp x10, x11, [sp, #0x10]
    str x12, [sp, #0x20]
.globl _v2call_file_op
_v2call_file_op:
    nop                               // sep_rpc.py 填成 bl 记录器（sep_trace.S）
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret

.globl _file_wrap_v2
_file_wrap_v2:
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    mov x3, x5
    mov x4, x6
    mov x5, x7
    ldr w6, [sp, #0x40]
    ldr x7, [sp, #0x68]               // v2 s40（= v1 s8，调用方 x26）；s8/s16 是 v2 新增的指针和长度
    ldr w8, [sp, #0x70]               // v2 s48（= v1 s16，调用方 [x29+0x20]）
    ldr w9, [sp, #0x74]
    ldr x10, [sp, #0x78]
    ldr w11, [sp, #0x80]
    ldp x12, x13, [sp, #0x88]
    ldr x14, [sp, #0x98]
    stp w8, w9, [sp]
    str x10, [sp, #8]
    str w11, [sp, #0x10]
    stp x12, x13, [sp, #0x18]
    str x14, [sp, #0x28]
.globl _v2call_file_wrap
_v2call_file_wrap:
    nop                               // sep_rpc.py 填成 bl 记录器（sep_trace.S）
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret

// SKS 16（AKS new_key：给新文件生成密钥）。v2 有 5 组输出（指针*, 长度*），v0 只有 3 组。
// iOS 14 在第 3 位插入了一组新的可选输出（主路径 0x66eb8ac 传 NULL/NULL），
// iOS 13 的第 3 组（包装后的密钥，APFS 写盘的 key_len 就来自它的长度）在 v2 里是第 4 组。
// 原先接成 v2 第 3 组：SEP 返回成功但包装密钥无处可写，长度停在 APFS 的初值 0x80，
// 盘上留下 0x80 字节的全零密钥，之后 unwrap(-11)/rewrap(-1) 全部失败。
.globl _file_unwrap_v2
_file_unwrap_v2:
    sub sp, sp, #0x50
    stp x29, x30, [sp, #0x40]
    add x29, sp, #0x40
    mov x4, x6
    mov x5, x7
    ldr x6, [sp, #0x50]
    ldr w7, [sp, #0x58]
    ldp x8, x9, [sp, #0x70]           // v2 输出 1（s0x20/s0x28）
    ldp x10, x11, [sp, #0x80]         // v2 输出 2（s0x30/s0x38）
    ldp x12, x13, [sp, #0xa0]         // v2 输出 4（s0x50/s0x58）= iOS 13 的输出 3；跳过新增的输出 3
    ldp x14, x15, [sp, #0xc0]
    stp x8, x9, [sp]
    stp x10, x11, [sp, #0x10]
    stp x12, x13, [sp, #0x20]
    stp x14, x15, [sp, #0x30]
.globl _v2call_file_unwrap
_v2call_file_unwrap:
    nop                               // sep_rpc.py 填成 bl 记录器（sep_trace.S）
    ldp x29, x30, [sp, #0x40]
    add sp, sp, #0x50
    ret
