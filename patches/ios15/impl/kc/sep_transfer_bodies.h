#ifndef N56_SEP_TRANSFER_BODIES_H
#define N56_SEP_TRANSFER_BODIES_H
#include "sep_transfer_runtime.h"
/* Preparation only: zero means valid/copied bytes, NEVER operation success.
 * No send, completion, storage write, wake, or endpoint publication here.
 * Outputs remain untouched on error except *written and *size=0 and *view=NULL.
 * ART/xART body copies permit exact alias only; ACM adds a header and requires
 * separate output storage. Length/view output slots must not alias byte buffers. */
st_i32 sep_transfer_acm_body(st_u32 command, const st_u8 *payload, st_u64 length,
                            st_u8 *out, st_u64 capacity, st_u64 *written);
st_i32 sep_transfer_art_storage_body(st_u32 opcode, const st_u8 *body, st_u64 length,
                                    st_u8 *out, st_u64 capacity, st_u64 *written);
/* header is xART's own 8B header, NOT ARTS or GT. Preserve endpoint/tag, flags,
 * UUID, and every payload byte. Caller must use its REAL xART endpoint; none is
 * published by this adapter. Fetch0/policy14 have no input OOL; UUID-only delete7 is byte-preserving.
 * Reply construction and policy semantics always remain native. */
st_i32 sep_transfer_xart_body(const st_u8 *header, const st_u8 *body, st_u64 length,
                             st_u8 *out_header, st_u8 *out, st_u64 capacity, st_u64 *written);
/* Bounded borrowed view through native 15 ART parser. A record must consume the
 * ENTIRE supplied record extent: trailing bytes are never silently discarded.
 * Exclude the native sleep sentinel from capacity. This does not persist/ACK;
 * retain save_incoming_art's bool and its real NVRAM set + FORCE sync path. */
st_i32 sep_transfer_art_record_view(const st_u8 *record, st_u64 capacity,
                                   const st_u8 **view, st_u64 *size);
#endif
