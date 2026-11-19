// Resume the one overwritten prologue word. No LSE, RCpc, PAC or atomics.
.text
.p2align 2
.globl _sep_transfer_acm_native_build
_sep_transfer_acm_native_build:
    sub sp, sp, #0x90
.globl _sep_transfer_acm_build_resume
_sep_transfer_acm_build_resume:
    nop
.globl _sep_transfer_xart_native_receive
_sep_transfer_xart_native_receive:
    sub sp, sp, #0xd0
.globl _sep_transfer_xart_receive_resume
_sep_transfer_xart_receive_resume:
    nop
