#ifndef N56_SEP_TRANSFER_RUNTIME_H
#define N56_SEP_TRANSFER_RUNTIME_H
/* Command translation belongs to the client (Mesa), not this wire engine.
 * descriptor bits 0..7 = native type, 8..23 = parameter/subcommand,
 * bit24 = type16 subchannel framing. bits25..31 must be zero.
 * Calling the installed GenericTransfer.transact hook additionally sets bit31;
 * direct exported transact_wire must NOT set bit31. flags must currently be 0.
 * For subchannel use type=0x16, parameter=old subcommand, bit24=1.
 * output/out_length must both be NULL or both non-NULL. Reply ownership uses
 * native IOMalloc/IOFree and transfers only on an actual completed valid reply.
 */
typedef unsigned char st_u8;
typedef unsigned short st_u16;
typedef unsigned int st_u32;
typedef unsigned long long st_u64;
typedef int st_i32;
#define SEP_TRANSFER_SUBCHANNEL (1U << 24)
#define SEP_TRANSFER_TAGGED_ENTRY (1U << 31)
#define SEP_TRANSFER_OWNER_MAGIC 0x32544753U /* 'SGT2', at object+b0 */
#define SEP_TRANSFER_HANDLED (1ULL << 32)
st_i32 sep_transfer_transact_wire(void *, st_u32, const st_u8 *, st_u64,
                                  st_u8 **, st_u64 *, st_u32);
st_i32 sep_transfer_transact_wire_iomd(void *, st_u32, const st_u8 *, st_u64,
                                       void *, st_u32 *, st_u32);
/* High32 == 1: low32 is callback IOReturn (NOT operation completion status).
 * High32 == 0: NOT OUR PACKET; caller MUST fall through to its original receiver.
 * Legacy notify types 0e/26/3e always fall through, even during a transaction.
 * Errors on a consumed transaction publish state.status and wake the waiter.
 */
st_u64 sep_transfer_receive_dispatch(void *, void *, const st_u64 *, void *);
/* Clear protocol/timeout quarantine only after endpoint is disabled/disconnected.
 * Cannot acknowledge recovery while an active/enabled endpoint may send stale
 * chunks. Returns Busy for an enabled endpoint or active transaction.
 */
st_i32 sep_transfer_clear_quarantine(void *);
#endif
