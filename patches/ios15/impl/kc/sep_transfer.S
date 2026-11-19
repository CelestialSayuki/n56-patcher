// 19H422 GenericTransfer raw-mailbox path. No gt_packet_t header is inspected.
// Normal FC/FD/FE GT traffic and all non-SBIO services retain their native path.
.text
.p2align 2
.equ GT_ENDPOINT_TAG, 0x1c
.equ ENDPOINT_SEND, 0xe8

.globl _sep_transfer_raw_dispatch
_sep_transfer_raw_dispatch:
    cbz x0, .Lnative
    ldr w8, [x0, #GT_ENDPOINT_TAG]
    mov w9, #0x696f
    movk w9, #0x7362, lsl #16       // 'sbio'
    cmp w8, w9
    b.ne .Lnative
    ubfx w8, w1, #8, #8
    cmp w8, #0xfc
    b.hs .Lnative
    b .Lsend_raw
.Lnative:
    // Replay exactly the overwritten instruction; native callee owns this frame.
    sub sp, sp, #0x70
.globl _sep_transfer_native_resume
_sep_transfer_native_resume:
    nop

// IOReturn send_raw(GenericTransfer *object, uint64_t mailbox_message).
// Caller owns the transaction lock, input/output buffers and legacy reply decoder.
// getEndpoint still does native service matching, workloop registration and binding.
// In particular this does NOT publish SBIO or pretend a GT transact has completed.
.globl _sep_transfer_send_raw
_sep_transfer_send_raw:
.Lsend_raw:
    cbz x0, .Lbad_argument
    sub sp, sp, #0x30
    stp x29, x30, [sp, #0x20]
    add x29, sp, #0x20
    str x1, [sp]
.globl _sep_transfer_get_endpoint
_sep_transfer_get_endpoint:
    nop
    cbz x0, .Loffline
    // Stack mailbox storage remains live until the synchronous send returns.
    ldr x8, [x0]
    ldr x8, [x8, #ENDPOINT_SEND]
    mov x1, sp
    mov x2, #0
    mov w3, #1
    blr x8
    b .Lreturn
.Loffline:
    mov w0, #0x2c7
    movk w0, #0xe000, lsl #16       // kIOReturnNotReady, not success
.Lreturn:
    ldp x29, x30, [sp, #0x20]
    add sp, sp, #0x30
    ret
.Lbad_argument:
    mov w0, #0x2c2
    movk w0, #0xe000, lsl #16       // kIOReturnBadArgument
    ret

// IOReturn send_endpoint(AppleSEPEndpoint *endpoint, uint64_t message).
// For ART/SCRD clients, which are NOT GenericTransfer objects. The caller must
// serialize the appropriate service's body, and must handle the actual reply.
.globl _sep_transfer_send_endpoint
_sep_transfer_send_endpoint:
    cbz x0, .Lbad_argument
    sub sp, sp, #0x20
    stp x29, x30, [sp, #0x10]
    add x29, sp, #0x10
    str x1, [sp]
    ldr x8, [x0]
    ldr x8, [x8, #ENDPOINT_SEND]
    mov x1, sp
    mov x2, #0
    mov w3, #1
    blr x8
    ldp x29, x30, [sp, #0x10]
    add sp, sp, #0x20
    ret
