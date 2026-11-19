/* Wire-identical bodies proved at native 12/14/15 callers AND receivers.
 * New credential types, xART policy command14 and persistence schemas are NOT
 * downgraded. These are explicit opt-in client helpers, not receive hooks. */
#include "sep_transfer_bodies.h"
#define BAD_ARGUMENT ((st_i32)0xe00002c2U)
#define UNSUPPORTED ((st_i32)0xe00002c7U)
#define MAX_ACM 0x1000U /* stage-one SCRD's real request buffer, including header */
#define ART_BUFFER 0x4000U
extern st_u64 sep_transfer_art_native_record_length(const st_u8 *, const st_u8 *);
static st_u32 u32(const st_u8 *p) {
    return p[0] | (st_u32)p[1] << 8 | (st_u32)p[2] << 16 | (st_u32)p[3] << 24;
}
static void copy(st_u8 *out, const st_u8 *p, st_u64 n) {
    for (st_u64 i = 0; i < n; ++i) out[i] = p[i];
}
static int overlap(const void *a, st_u64 an, const void *b, st_u64 bn) {
    st_u64 x = (st_u64)a, y = (st_u64)b;
    if (!an || !bn) return 0;
    return x <= y ? y - x < an : x - y < bn;
}
static int writable(const st_u8 *p, st_u64 n, st_u8 *out, st_u64 capacity) {
    return (!n || (p && out)) && n <= capacity &&
           (p == out || !overlap(p, n, out, n));
}
st_i32 sep_transfer_acm_body(st_u32 command, const st_u8 *p, st_u64 n,
                            st_u8 *out, st_u64 capacity, st_u64 *written) {
    if (!written) return BAD_ARGUMENT;
    *written = 0;
    if ((n && !p) || n > MAX_ACM - 8) return BAD_ARGUMENT;
    switch (command) {
    case 1: if (n) return BAD_ARGUMENT; break;
    case 2: case 18: if (n != 16) return BAD_ARGUMENT; break;
    case 9: if (n != 24) return BAD_ARGUMENT; break;
    case 5: case 6: {
        /* handle16 + credential{header32 + data[len@1c]} + scope32.
         * 12 accepts types1..12; 14/15 exclude11 and extend beyond12.
         * Common set1..10,12 only; no invented replacement for types13..19. */
        if (n < 52 || u32(p + 44) != n - 52) return BAD_ARGUMENT;
        st_u32 type = u32(p + 16);
        if (!((type >= 1 && type <= 10) || type == 12)) return UNSUPPORTED;
        break;
    }
    default: return UNSUPPORTED;
    }
    if (!out || capacity < n + 8 || overlap(p, n, out, n + 8)) return BAD_ARGUMENT;
    /* LibCall_BuildCommand: SCRD magic LE, command, version0, flags0, reserved0. */
    out[0] = 0x44; out[1] = 0x52; out[2] = 0x43; out[3] = 0x53;
    out[4] = command; out[5] = 0; out[6] = 0; out[7] = 0;
    if (n) copy(out + 8, p, n);
    *written = n + 8;
    return 0;
}
st_i32 sep_transfer_art_storage_body(st_u32 opcode, const st_u8 *p, st_u64 n,
                                    st_u8 *out, st_u64 capacity, st_u64 *written) {
    if (!written) return BAD_ARGUMENT;
    *written = 0;
    if (opcode != 1 && opcode != 2 && opcode != 3) return UNSUPPORTED;
    if (opcode == 2 ? n != 0 : n == 0 || n >= ART_BUFFER) return BAD_ARGUMENT;
    if (!writable(p, n, out, capacity)) return BAD_ARGUMENT;
    if (n) copy(out, p, n);
    *written = n;
    return 0; /* opaque DER manifest/ART_LOAD copied verbatim, not transcoded */
}
st_i32 sep_transfer_xart_body(const st_u8 *h, const st_u8 *p, st_u64 n,
                             st_u8 *oh, st_u8 *out, st_u64 capacity, st_u64 *written) {
    if (!written) return BAD_ARGUMENT;
    *written = 0;
    if (!h || !oh) return BAD_ARGUMENT;
    st_u32 command = h[2], length = h[3] | (st_u32)h[4] << 8;
    /* No response-bit shift: xART command byte doubles as reply status. */
    if (command != 0 && command != 1 && command != 5 && command != 6 && command != 7 && command != 14) return UNSUPPORTED;
    if (h[5] > 1) return UNSUPPORTED;
    /* +6 is CRC16, NOT reserved. Preserve even a bad CRC: native receiver
     * checks it and must publish its real status before any persistence ACK. */
    if (command == 0 || command == 14) {
        /* Fetch0 has NO input OOL (length is receive capacity); policy14 has
         * NO body. Native code alone builds returned flag/UUID/data/status. */
        if (n || (command == 0 ? length > 0x7fef : length != 0)) return BAD_ARGUMENT;
    } else if (n != length || (command == 1 ? n > 0x7fef :
        command == 5 || command == 7 ? n != 16 : n < 16 || n > 0x8000)) return BAD_ARGUMENT;
    if (!writable(p, n, out, capacity) || (h != oh && overlap(h, 8, oh, 8)) ||
        overlap(h, 8, out, n) || overlap(oh, 8, p, n) || overlap(oh, 8, out, n)) return BAD_ARGUMENT;
    copy(oh, h, 8);
    if (n) copy(out, p, n);
    *written = n;
    return 0;
}
st_i32 sep_transfer_art_record_view(const st_u8 *p, st_u64 capacity,
                                   const st_u8 **view, st_u64 *size) {
    if (view) *view = 0;
    if (size) *size = 0;
    if (!p || !view || !size || !capacity || capacity >= ART_BUFFER ||
        (st_u64)p > ~(st_u64)0 - capacity) return BAD_ARGUMENT;
    st_u64 n = sep_transfer_art_native_record_length(p, p + capacity);
    if (!n || n != capacity) return BAD_ARGUMENT;
    *view = p; *size = n;
    return 0;
}
