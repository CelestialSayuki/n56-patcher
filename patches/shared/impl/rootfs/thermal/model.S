// N56 temperature formulas from Apple ThermalMonitor 131 (iOS 12.5.8).
// References resolve to the target daemon's code and metadata at build time.
.text
.p2align 2
.globl _n56_gas_temperature
_n56_gas_temperature:
    adrp x8, _n56_input_values@PAGE
    ldr x8, [x8, _n56_input_values@PAGEOFF]
    ldr w0, [x8]
    ret
.globl _n56_update_thermal_load
_n56_update_thermal_load:
    sub sp, sp, #0xa0
    stp d13, d12, [sp, #0x10]
    stp d11, d10, [sp, #0x20]
    stp d9, d8, [sp, #0x30]
    stp x28, x27, [sp, #0x40]
    stp x26, x25, [sp, #0x50]
    stp x24, x23, [sp, #0x60]
    stp x22, x21, [sp, #0x70]
    stp x20, x19, [sp, #0x80]
    stp x29, x30, [sp, #0x90]
    add x29, sp, #0x90
    mov x19, x0
    adrp x1, _n56_sel_gasGaugeBatteryTemperature@PAGE
    ldr x1, [x1, _n56_sel_gasGaugeBatteryTemperature@PAGEOFF]
    bl _objc_msgSend
    mov x22, x0
    adrp x24, _n56_input_values@PAGE
    ldr x24, [x24, _n56_input_values@PAGEOFF]
    ldp w25, w8, [x24, #4]
    str w8, [sp, #8]
    ldp w8, w26, [x24, #0xc]
    str w8, [sp, #0xc]
    ldr w27, [x24, #0x60]
    adrp x20, _n56_sel_findComponent@PAGE
    ldr x20, [x20, _n56_sel_findComponent@PAGEOFF]
    mov w2, #0xd
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    mov x23, x0
    adrp x1, _n56_sel_dieTempMaxAverage@PAGE
    ldr x1, [x1, _n56_sel_dieTempMaxAverage@PAGEOFF]
    mov x0, x19
    bl _objc_msgSend
    scvtf d0, w0
    nop
    ldr d11, Lconstant_50bf0
    fdiv d0, d0, d11
    fcvt s0, d0
    adrp x21, _n56_sel_calculateControlEffort@PAGE
    ldr x21, [x21, _n56_sel_calculateControlEffort@PAGEOFF]
    mov x0, x23
    mov x1, x21
    bl _objc_msgSend
    mov w2, #0
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    adrp x1, _n56_sel_currentLoadingIndex@PAGE
    ldr x1, [x1, _n56_sel_currentLoadingIndex@PAGEOFF]
    bl _objc_msgSend
    mul w8, w0, w0
    scvtf d0, w8
    fdiv d0, d0, d11
    fcvt s0, d0
    adrp x23, _n56_power_filtered@PAGE
    ldr s1, [x23, _n56_power_filtered@PAGEOFF]
    fcmp s1, #0.0
    b.mi Lcode_a014
    fsub s0, s0, s1
    nop
    ldr s2, Lconstant_50de0
    fmul s0, s0, s2
    fadd s0, s1, s0
Lcode_a014:
    str s0, [x23, _n56_power_filtered@PAGEOFF]
    bic w8, w27, w27, asr #31
    adrp x28, _n56_power_filtered@PAGE
    ldr w9, [x28, _n56_power_slow@PAGEOFF]
    mov x10, x8
    tbnz w9, #0x1f, Lcode_a04c
    sub w10, w8, w9
    scvtf s0, w10
    nop
    ldr s1, Lconstant_50de4
    fmul s0, s0, s1
    scvtf s1, w9
    fadd s0, s0, s1
    fcvtzs w10, s0
Lcode_a04c:
    str w10, [x28, _n56_power_slow@PAGEOFF]
    adrp x27, _n56_power_filtered@PAGE
    ldr w9, [x27, _n56_power_fast@PAGEOFF]
    tbnz w9, #0x1f, Lcode_a07c
    sub w8, w8, w9
    scvtf s0, w8
    nop
    ldr s1, Lconstant_50de0
    fmul s0, s0, s1
    scvtf s1, w9
    fadd s0, s0, s1
    fcvtzs w8, s0
Lcode_a07c:
    str w8, [x27, _n56_power_fast@PAGEOFF]
    scvtf d12, w22
    nop
    ldr d0, Lconstant_50cf8
    fmul d0, d12, d0
    nop
    ldr d1, Lconstant_50d00
    fadd d0, d0, d1
    scvtf d8, w26
    nop
    ldr d9, Lconstant_50d08
    fmul d1, d8, d9
    fadd d0, d0, d1
    scvtf d10, w25
    nop
    ldr d1, Lconstant_50d10
    fmul d1, d10, d1
    fadd d0, d1, d0
    fcvtzs w1, d0
    mov w0, #0x19
    bl _n56_set_virtual_temperature
    nop
    ldr d0, Lconstant_50d18
    fmul d0, d12, d0
    nop
    ldr d1, Lconstant_50d20
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50d28
    fmul d1, d8, d1
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50d30
    fmul d1, d10, d1
    fadd d0, d1, d0
    fcvtzs w1, d0
    mov w0, #0x1b
    bl _n56_set_virtual_temperature
    nop
    ldr d0, Lconstant_50d38
    fmul d0, d12, d0
    nop
    ldr d1, Lconstant_50d40
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50d48
    fmul d1, d8, d1
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50d50
    fmul d1, d10, d1
    fadd d0, d1, d0
    fcvtzs w1, d0
    mov w0, #0x1c
    bl _n56_set_virtual_temperature
    nop
    ldr d0, Lconstant_50d58
    fmul d0, d12, d0
    nop
    ldr d1, Lconstant_50d60
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50d68
    fmul d1, d8, d1
    fadd d0, d0, d1
    ldr w8, [sp, #8]
    scvtf d1, w8
    nop
    ldr d2, Lconstant_50d70
    fmul d1, d1, d2
    fadd d0, d1, d0
    fcvtzs w1, d0
    mov w0, #0x1d
    bl _n56_set_virtual_temperature
    nop
    ldr d0, Lconstant_50d78
    fmul d0, d8, d0
    nop
    ldr d1, Lconstant_50d80
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50d88
    fmul d1, d10, d1
    fadd d0, d1, d0
    ldr w8, [x28, _n56_power_slow@PAGEOFF]
    scvtf d1, w8
    nop
    ldr d2, Lconstant_50d90
    fmul d1, d1, d2
    fadd d0, d0, d1
    ldr s1, [x23, _n56_power_filtered@PAGEOFF]
    fcvt d1, s1
    nop
    ldr d2, Lconstant_50d98
    fmul d1, d1, d2
    fadd d0, d0, d1
    fcvtzs w1, d0
    mov w0, #0x1a
    bl _n56_set_virtual_temperature
    nop
    ldr d0, Lconstant_50da0
    fmul d0, d12, d0
    nop
    ldr d1, Lconstant_50da8
    fadd d0, d0, d1
    ldr w8, [sp, #0xc]
    scvtf d1, w8
    nop
    ldr d2, Lconstant_50db0
    fmul d1, d1, d2
    fadd d0, d0, d1
    fmul d1, d10, d9
    fadd d0, d1, d0
    fcvtzs w1, d0
    mov w0, #0x1e
    bl _n56_set_virtual_temperature
    nop
    ldr d0, Lconstant_50db8
    fmul d0, d12, d0
    nop
    ldr d1, Lconstant_50dc0
    fadd d0, d0, d1
    nop
    ldr d1, Lconstant_50dc8
    fmul d1, d8, d1
    fadd d0, d0, d1
    ldr w8, [x27, _n56_power_fast@PAGEOFF]
    scvtf d1, w8
    nop
    ldr d2, Lconstant_50dd0
    fmul d1, d1, d2
    fadd d0, d0, d1
    ldr s1, [x23, _n56_power_filtered@PAGEOFF]
    fcvt d1, s1
    nop
    ldr d2, Lconstant_50dd8
    fmul d1, d1, d2
    fadd d0, d0, d1
    fcvtzs w1, d0
    mov w0, #0x1f
    bl _n56_set_virtual_temperature
    ldr s0, [x24, #0x78]
    scvtf s8, s0
    mov w2, #0xe
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    fcvt d0, s8
    fdiv d8, d0, d11
    fcvt s0, d8
    mov x1, x21
    bl _objc_msgSend
    ldr s0, [x24, #0x70]
    scvtf s9, s0
    mov w2, #0xf
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    nop
    ldr s10, Lconstant_50bf8
    fdiv s9, s9, s10
    mov v0.16b, v9.16b
    mov x1, x21
    bl _objc_msgSend
    mov w2, #0x10
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    mov v0.16b, v9.16b
    mov x1, x21
    bl _objc_msgSend
    ldr s0, [x24, #0x7c]
    scvtf s9, s0
    mov w2, #0x11
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    fdiv s0, s9, s10
    mov x1, x21
    bl _objc_msgSend
    ldr s0, [x24, #0x74]
    scvtf s9, s0
    mov w2, #0x12
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    fcvt d0, s9
    fdiv d9, d0, d11
    fcvt s10, d9
    mov v0.16b, v10.16b
    mov x1, x21
    bl _objc_msgSend
    mov w2, #0x13
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    mov v0.16b, v10.16b
    mov x1, x21
    bl _objc_msgSend
    ldr s0, [x24, #0x68]
    scvtf s10, s0
    mov w2, #0x14
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    fcvt d0, s10
    fdiv d10, d0, d11
    fcvt s0, d10
    mov x1, x21
    bl _objc_msgSend
    adrp x0, _n56_class_ContextAwareThermalManager@PAGE
    ldr x0, [x0, _n56_class_ContextAwareThermalManager@PAGEOFF]
    adrp x1, _n56_sel_sharedInstance@PAGE
    ldr x1, [x1, _n56_sel_sharedInstance@PAGEOFF]
    bl _objc_msgSend
    adrp x1, _n56_sel_isContextTriggered@PAGE
    ldr x1, [x1, _n56_sel_isContextTriggered@PAGEOFF]
    mov w2, #0
    bl _objc_msgSend
    mov x20, x0
    nop
    adrp x22, _n56_ivar_aggdTM@PAGE
    ldrsw x22, [x22, _n56_ivar_aggdTM@PAGEOFF]
    ldr x0, [x19, x22]
    adrp x21, _n56_sel_updateAggregateDictStats@PAGE
    ldr x21, [x21, _n56_sel_updateAggregateDictStats@PAGEOFF]
    mov v0.16b, v9.16b
    mov w2, #0
    mov x3, x20
    mov x1, x21
    bl _objc_msgSend
    ldr x0, [x19, x22]
    mov w2, #1
    mov v0.16b, v8.16b
    mov x3, x20
    mov x1, x21
    bl _objc_msgSend
    ldr x0, [x19, x22]
    fdiv d0, d12, d11
    mov w2, #2
    mov x3, x20
    mov x1, x21
    bl _objc_msgSend
    ldr x0, [x19, x22]
    mov w2, #3
    mov v0.16b, v10.16b
    mov x3, x20
    mov x1, x21
    ldp x29, x30, [sp, #0x90]
    ldp x20, x19, [sp, #0x80]
    ldp x22, x21, [sp, #0x70]
    ldp x24, x23, [sp, #0x60]
    ldp x26, x25, [sp, #0x50]
    ldp x28, x27, [sp, #0x40]
    ldp d9, d8, [sp, #0x30]
    ldp d11, d10, [sp, #0x20]
    ldp d13, d12, [sp, #0x10]
    add sp, sp, #0xa0
    b _objc_msgSend
.globl _n56_suppress_behaviors
_n56_suppress_behaviors:
    stp d9, d8, [sp, #-0x50]!
    stp x24, x23, [sp, #0x10]
    stp x22, x21, [sp, #0x20]
    stp x20, x19, [sp, #0x30]
    stp x29, x30, [sp, #0x40]
    add x29, sp, #0x40
    mov x19, x0
    adrp x20, _n56_sel_findComponent@PAGE
    ldr x20, [x20, _n56_sel_findComponent@PAGEOFF]
    mov w2, #0
    mov x1, x20
    bl _objc_msgSend
    adrp x1, _n56_sel_initBrightnessTable@PAGE
    ldr x1, [x1, _n56_sel_initBrightnessTable@PAGEOFF]
    mov x2, #0
    bl _objc_msgSend
    adrp x21, _n56_sel_setTHERMAL_TRAP_LOAD@PAGE
    ldr x21, [x21, _n56_sel_setTHERMAL_TRAP_LOAD@PAGEOFF]
    adrp x22, _n56_sel_setTHERMAL_TRAP_SLEEP@PAGE
    ldr x22, [x22, _n56_sel_setTHERMAL_TRAP_SLEEP@PAGEOFF]
    mov w23, #0xd
    nop
    ldr s8, Lconstant_50de8
    nop
    ldr s9, Lconstant_50dec
Lcode_a4ec:
    mov x2, x23
    mov x0, x19
    mov x1, x20
    bl _objc_msgSend
    mov x24, x0
    mov v0.16b, v8.16b
    mov x1, x21
    bl _objc_msgSend
    mov v0.16b, v9.16b
    mov x0, x24
    mov x1, x22
    bl _objc_msgSend
    add w23, w23, #1
    cmp w23, #0x15
    b.ne Lcode_a4ec
    ldp x29, x30, [sp, #0x40]
    ldp x20, x19, [sp, #0x30]
    ldp x22, x21, [sp, #0x20]
    ldp x24, x23, [sp, #0x10]
    ldp d9, d8, [sp], #0x50
    ret
.p2align 3
Lconstant_50bf0:
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x40
.p2align 3
Lconstant_50de0:
    .byte 0xcd, 0xcc, 0x4c, 0x3e
.p2align 3
Lconstant_50de4:
    .byte 0xd9, 0x89, 0x9d, 0x3d
.p2align 3
Lconstant_50cf8:
    .byte 0x48, 0x50, 0xfc, 0x18, 0x73, 0xd7, 0xda, 0x3f
.p2align 3
Lconstant_50d00:
    .byte 0xfb, 0x3a, 0x70, 0xce, 0x88, 0xb6, 0x57, 0x40
.p2align 3
Lconstant_50d08:
    .byte 0x6b, 0x9a, 0x77, 0x9c, 0xa2, 0x23, 0xc9, 0x3f
.p2align 3
Lconstant_50d10:
    .byte 0xe8, 0x6a, 0x2b, 0xf6, 0x97, 0xdd, 0xd7, 0x3f
.p2align 3
Lconstant_50d18:
    .byte 0x88, 0x63, 0x5d, 0xdc, 0x46, 0x03, 0xea, 0x3f
.p2align 3
Lconstant_50d20:
    .byte 0x7e, 0x8c, 0xb9, 0x6b, 0x09, 0x71, 0x53, 0x40
.p2align 3
Lconstant_50d28:
    .byte 0x39, 0xd6, 0xc5, 0x6d, 0x34, 0x80, 0xa7, 0xbf
.p2align 3
Lconstant_50d30:
    .byte 0x29, 0x5c, 0x8f, 0xc2, 0xf5, 0x28, 0xcc, 0x3f
.p2align 3
Lconstant_50d38:
    .byte 0x8e, 0x75, 0x71, 0x1b, 0x0d, 0xe0, 0xd1, 0x3f
.p2align 3
Lconstant_50d40:
    .byte 0x52, 0xb8, 0x1e, 0x85, 0xeb, 0x51, 0x20, 0x40
.p2align 3
Lconstant_50d48:
    .byte 0xbe, 0xc1, 0x17, 0x26, 0x53, 0x05, 0xb3, 0x3f
.p2align 3
Lconstant_50d50:
    .byte 0xcb, 0xa1, 0x45, 0xb6, 0xf3, 0xfd, 0xe4, 0x3f
.p2align 3
Lconstant_50d58:
    .byte 0xac, 0x8b, 0xdb, 0x68, 0x00, 0x6f, 0xe1, 0x3f
.p2align 3
Lconstant_50d60:
    .byte 0x63, 0xee, 0x5a, 0x42, 0x3e, 0x14, 0x52, 0x40
.p2align 3
Lconstant_50d68:
    .byte 0x58, 0x39, 0xb4, 0xc8, 0x76, 0xbe, 0xaf, 0x3f
.p2align 3
Lconstant_50d70:
    .byte 0xb1, 0xe1, 0xe9, 0x95, 0xb2, 0x0c, 0xd9, 0x3f
.p2align 3
Lconstant_50d78:
    .byte 0x02, 0x2b, 0x87, 0x16, 0xd9, 0xce, 0xa7, 0xbf
.p2align 3
Lconstant_50d80:
    .byte 0xad, 0x69, 0xde, 0x71, 0x8a, 0x5f, 0x79, 0x40
.p2align 3
Lconstant_50d88:
    .byte 0xb6, 0x84, 0x7c, 0xd0, 0xb3, 0x59, 0xef, 0x3f
.p2align 3
Lconstant_50d90:
    .byte 0x9c, 0xc4, 0x20, 0xb0, 0x72, 0x68, 0xa1, 0x3f
.p2align 3
Lconstant_50d98:
    .byte 0x20, 0x41, 0xf1, 0x63, 0xcc, 0xdd, 0x0d, 0x40
.p2align 3
Lconstant_50da0:
    .byte 0x69, 0x00, 0x6f, 0x81, 0x04, 0xc5, 0xdf, 0x3f
.p2align 3
Lconstant_50da8:
    .byte 0xb4, 0xc8, 0x76, 0xbe, 0x9f, 0x6a, 0x43, 0x40
.p2align 3
Lconstant_50db0:
    .byte 0x32, 0xe6, 0xae, 0x25, 0xe4, 0x83, 0xd2, 0x3f
.p2align 3
Lconstant_50db8:
    .byte 0x06, 0x12, 0x14, 0x3f, 0xc6, 0xdc, 0xe5, 0x3f
.p2align 3
Lconstant_50dc0:
    .byte 0xdd, 0xb5, 0x84, 0x7c, 0xd0, 0xd9, 0x80, 0xc0
.p2align 3
Lconstant_50dc8:
    .byte 0x52, 0x27, 0xa0, 0x89, 0xb0, 0xe1, 0xc1, 0x3f
.p2align 3
Lconstant_50dd0:
    .byte 0xbc, 0x96, 0x90, 0x0f, 0x7a, 0x36, 0xd3, 0x3f
.p2align 3
Lconstant_50dd8:
    .byte 0x70, 0x5f, 0x07, 0xce, 0x19, 0xd1, 0x05, 0x40
.p2align 3
Lconstant_50bf8:
    .byte 0x00, 0x00, 0xc8, 0x42
.p2align 3
Lconstant_50de8:
    .byte 0x00, 0x00, 0x64, 0x42
.p2align 3
Lconstant_50dec:
    .byte 0x00, 0x00, 0x68, 0x42
.data
.p2align 2
.globl _n56_power_filtered
_n56_power_filtered:
    .long 0xbf800000
.globl _n56_power_slow
_n56_power_slow:
    .long -1
.globl _n56_power_fast
_n56_power_fast:
    .long -1
