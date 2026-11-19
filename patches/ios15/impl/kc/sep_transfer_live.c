/* Real AP caller/receiver hooks. Identity bodies are prepared in the actual
 * chain; unsupported preparation ALWAYS keeps the native body and errors.
 * No send/ACK/persistence replacement. All ownership remains with native code. */
#include "sep_transfer_bodies.h"
extern st_u8 *sep_transfer_acm_native_build(st_u32, st_u32, st_u32, const st_u8 *, st_u64, st_u64 *);
extern void sep_transfer_xart_native_receive(void *, st_u8 *);
extern void *sep_transfer_live_native_copy(void *, const void *, st_u64);
extern st_u64 sep_transfer_art_native_record_length(const st_u8 *, const st_u8 *);

st_u8 *sep_transfer_acm_build_live(st_u32 command, st_u32 version, st_u32 flags,
                                  const st_u8 *payload, st_u64 n, st_u64 *size) {
    /* Native allocation, zero-fill, size/overflow validation and NULL result
     * are authoritative. Helper error never becomes an ACM operation error. */
    st_u8 *result = sep_transfer_acm_native_build(command, version, flags, payload, n, size);
    if (result && size && n <= 0xff8 && *size == n + 8 && !version && !flags && !result[7]) {
        st_u64 prepared = 0;
        (void)sep_transfer_acm_body(command, payload, n, result, *size, &prepared);
    }
    return result;
}
static void *art_copy(st_u32 command, void *dest, const void *source, st_u64 n) {
    st_u64 prepared = 0;
    if (!sep_transfer_art_storage_body(command, source, n, dest, n, &prepared)) return dest;
    return sep_transfer_live_native_copy(dest, source, n); /* unchanged native failure/large-body path */
}
void *sep_transfer_art_manifest_copy_live(void *dest, const void *source, st_u64 n) {
    return art_copy(3, dest, source, n);
}
void *sep_transfer_art_load_copy_live(void *dest, const void *source, st_u64 n) {
    return art_copy(1, dest, source, n);
}
st_u64 sep_transfer_art_persist_length_live(const st_u8 *record, const st_u8 *end) {
    st_u64 n = sep_transfer_art_native_record_length(record, end);
    if (n && (st_u64)end >= (st_u64)record && n <= (st_u64)end - (st_u64)record) {
        const st_u8 *view = 0; st_u64 size = 0;
        /* Native buffer extent can include padding/sentinel; pass ONLY the
         * parser's exact record extent to the helper, never discard its tail. */
        (void)sep_transfer_art_record_view(record, n, &view, &size);
    }
    return n; /* original parse length/error; real persist_art and bool->ACK remain native */
}
void sep_transfer_xart_receive_live(void *object, st_u8 *header) {
    if (object && header) {
        st_u8 *body = *(st_u8 **)((st_u8 *)object + 0xd0);
        st_u64 n = header[3] | (st_u64)header[4] << 8;
        if ((body || header[2] == 0 || header[2] == 14) && n <= 0x8000) {
            st_u64 prepared = 0;
            /* Same header/body pointers: exact identity only. Native receiver
             * still checks CRC, accesses gigalocker and sets its real status. */
            st_u64 input_size = header[2] == 0 || header[2] == 14 ? 0 : n;
            (void)sep_transfer_xart_body(header, body, input_size, header, body, 0x8000, &prepared);
        }
    }
    sep_transfer_xart_native_receive(object, header);
}
