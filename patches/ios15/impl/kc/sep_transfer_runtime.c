/* Shared 19H422 <-> 16H88 SBIO wire engine; no Mesa operation conversion.
 * Protocol evidence: native12 8609344..86095d8 (0x16/17/18 receive), 86134ec
 * first transmit, and iOS14 mesa_transport.c. Receive sequence is NOT reset
 * between request chunks and reply chunks (native12 8609518).
 */
#include "sep_transfer_runtime.h"

#define CHUNK 0x1000U
#define MAX_TRANSFER 0x4b000U
#define BAD_ARGUMENT ((st_i32)0xe00002c2U)
#define NOT_READY ((st_i32)0xe00002c7U)
#define OFFLINE ((st_i32)0xe00002c9U)
#define NO_MEMORY ((st_i32)0xe00002bdU)
#define BUSY ((st_i32)0xe00002d5U)
#define UNSUPPORTED ((st_i32)0xe00002c7U)
#define INVALID_REPLY 22

enum { IDLE, DIRECT_REPLY, SENDING, RECEIVING, COMPLETE };
enum { PHASE = 255, OWNED = 256 };
typedef struct {
    st_u8 *data;
    st_u64 total, offset;
    st_u16 sequence, command;
    st_u32 descriptor;
    st_i32 status;
    st_u32 flags, wire, reserved;
} State;
_Static_assert(sizeof(State) == 0x30, "client state fits +80..af");
_Static_assert(__builtin_offsetof(State, flags) == 0x24, "legacy Mesa-compatible phase");

extern void *sep_transfer_get_endpoint(void *);
extern st_i32 sep_transfer_lock(void *, st_u32);
extern void sep_transfer_unlock(void *);
extern st_i32 sep_transfer_wait(void *, st_u32);
extern void sep_transfer_wake(void *);
extern void *sep_transfer_alloc(st_u64);
extern void sep_transfer_free(void *, st_u64);
extern void sep_transfer_copy(void *, const void *, st_u64);
extern void sep_transfer_zero(void *, int, st_u64);

static void *ptr(void *o, st_u32 at) { return *(void **)((st_u8 *)o + at); }
static State *state(void *o) { return (State *)((st_u8 *)o + 0x80); }
static st_u32 *marker(void *o) { return (st_u32 *)((st_u8 *)o + 0xb0); }
#define RX_BUSY 0x80000000U
static st_u32 *quarantine(void *o) { return (st_u32 *)((st_u8 *)o + 0xb4); }
static st_u32 phase(State *s) { return __atomic_load_n(&s->flags, __ATOMIC_ACQUIRE) & PHASE; }
static st_u64 minimum(st_u64 a, st_u64 b) { return a < b ? a : b; }
static int sbio(void *o) { return o && *(st_u32 *)((st_u8 *)o + 0x1c) == 0x7362696fU; }

static st_i32 send(void *o, st_u8 type, st_u16 parameter, st_u16 length) {
    void *ep = ptr(o, 0x28);
    if (!ep) return NOT_READY;
    typedef st_i32 (*Send)(void *, const st_u64 *, void *, st_u32);
    Send fn = *(Send *)(*(st_u8 **)ep + 0xe8);
    st_u64 word = 8 | ((st_u64)type << 8) | ((st_u64)parameter << 16) | ((st_u64)length << 48);
    return fn(ep, &word, 0, 1);
}

static void complete(void *o, State *s, st_i32 error, int poison) {
    if (poison) __atomic_store_n(quarantine(o), 1, __ATOMIC_RELEASE);
    s->status = error;
    __atomic_store_n(&s->flags, (s->flags & OWNED) | COMPLETE, __ATOMIC_RELEASE);
    sep_transfer_wake(ptr(o, 0x10));
}

static void direct_reply(void *o, State *s, st_u64 word) {
    st_u64 length = word >> 48;
    st_i32 error = (short)(word >> 16);
    if (length > CHUNK) { complete(o, s, INVALID_REPLY, 1); return; }
    if (error) { complete(o, s, error, 0); return; }
    s->data = 0; s->total = length; s->offset = length;
    if (length) {
        s->data = sep_transfer_alloc(length);
        if (!s->data) { complete(o, s, NO_MEMORY, 0); return; }
        s->flags |= OWNED;
        sep_transfer_copy(s->data, ptr(o, 0x68), length);
    }
    complete(o, s, 0, 0);
}

static void first_reply(void *o, State *s, st_u64 word) {
    st_u64 length = word >> 48;
    st_u8 *buffer = ptr(o, 0x68);
    if (phase(s) != SENDING || s->offset != s->total ||
        (st_u16)(word >> 16) || length < 8 || length > CHUNK) {
        complete(o, s, INVALID_REPLY, 1); return;
    }
    st_u64 total = *(st_u32 *)buffer;
    st_u16 command = *(st_u16 *)(buffer + 4);
    st_i32 error = *(short *)(buffer + 6);
    st_u64 chunk = length - 8;
    if (command != (st_u16)(s->command | 0x8000U) || total > MAX_TRANSFER ||
        total > *(st_u32 *)((st_u8 *)o + 0x18) || chunk != minimum(total, CHUNK - 8)) {
        complete(o, s, INVALID_REPLY, 1); return;
    }
    if (error) { complete(o, s, error, 0); return; }
    /* Input is borrowed. Do not free it when switching to an owned reply. */
    s->data = 0; s->total = total; s->offset = chunk;
    s->flags = RECEIVING;
    if (total) {
        s->data = sep_transfer_alloc(total);
        if (!s->data) { complete(o, s, NO_MEMORY, 1); return; }
        s->flags |= OWNED;
        if (chunk) sep_transfer_copy(s->data, buffer + 8, chunk);
    }
    if (chunk == total) { complete(o, s, 0, 0); return; }
    st_i32 status = send(o, 0x18, 0, 0);
    if (status) complete(o, s, status, 1);
}

static void receive_chunk(void *o, State *s, st_u64 word) {
    st_u64 length = word >> 48;
    st_u16 sequence = word >> 16;
    if (phase(s) != RECEIVING || s->offset >= s->total || !s->data ||
        sequence != (st_u16)(s->sequence + 1) ||
        length != minimum(s->total - s->offset, CHUNK)) {
        complete(o, s, INVALID_REPLY, 1); return;
    }
    sep_transfer_copy(s->data + s->offset, ptr(o, 0x68), length);
    s->offset += length; s->sequence = sequence;
    if (s->offset == s->total) { complete(o, s, 0, 0); return; }
    st_i32 status = send(o, 0x18, 0, 0);
    if (status) complete(o, s, status, 1);
}

static void send_chunk(void *o, State *s, st_u64 word) {
    if (phase(s) != SENDING || (st_u16)(word >> 16) || (word >> 48) ||
        s->offset >= s->total || !s->data) {
        complete(o, s, INVALID_REPLY, 1); return;
    }
    st_u64 length = minimum(s->total - s->offset, CHUNK);
    sep_transfer_copy(ptr(o, 0x50), s->data + s->offset, length);
    s->offset += length;
    st_u16 sequence = s->sequence++;
    st_i32 status = send(o, 0x17, sequence, length);
    if (status) complete(o, s, status, 1);
}

st_u64 sep_transfer_receive_dispatch(void *o, void *context, const st_u64 *message, void *callback) {
    (void)context; (void)callback;
    if (!sbio(o)) return 0;
    st_u32 owned = __atomic_load_n(marker(o), __ATOMIC_ACQUIRE);
    if ((owned & ~RX_BUSY) != SEP_TRANSFER_OWNER_MAGIC) return 0;
    st_u64 word = message ? *message : 0;
    st_u8 type = word >> 8;
    if (message && (type == 0x0e || type == 0x26 || type == 0x3e)) return 0;
    st_u32 expected = SEP_TRANSFER_OWNER_MAGIC;
    if (!__atomic_compare_exchange_n(marker(o), &expected, SEP_TRANSFER_OWNER_MAGIC | RX_BUSY,
                                     0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return SEP_TRANSFER_HANDLED | (st_u32)BUSY;
    /* Prevent a timeout waiter from clearing/freeing state while an IRQ receiver
     * owns it. Workloop callbacks are serialized; the marker also covers teardown. */
    State *s = state(o);
    st_u64 result = SEP_TRANSFER_HANDLED;
    st_u32 p = phase(s);
    if (!message) {
        complete(o, s, BAD_ARGUMENT, 1);
        result |= (st_u32)BAD_ARGUMENT;
    } else if (p == COMPLETE || p == IDLE) result |= (st_u32)NOT_READY;
    else if ((st_u8)word != 8) complete(o, s, INVALID_REPLY, 1);
    else if (p == DIRECT_REPLY && type == s->wire) direct_reply(o, s, word);
    else if (p == SENDING && type == 0x16) first_reply(o, s, word);
    else if (p == RECEIVING && type == 0x17) receive_chunk(o, s, word);
    else if (p == SENDING && type == 0x18) send_chunk(o, s, word);
    else complete(o, s, INVALID_REPLY, 1);
    __atomic_store_n(marker(o), SEP_TRANSFER_OWNER_MAGIC, __ATOMIC_RELEASE);
    return result; /* operation status is separately published in state.status */
}

st_i32 sep_transfer_transact_wire(void *o, st_u32 descriptor, const st_u8 *input, st_u64 length,
                                 st_u8 **output, st_u64 *out_length, st_u32 flags) {
    if (output) *output = 0;
    if (out_length) *out_length = 0;
    if (!sbio(o) || (output == 0) != (out_length == 0) || (length && !input) ||
        length > MAX_TRANSFER || length > *(st_u32 *)((st_u8 *)o + 0x18)) return BAD_ARGUMENT;
    st_u8 type = descriptor;
    int sub = (descriptor & SEP_TRANSFER_SUBCHANNEL) != 0;
    st_u16 parameter = descriptor >> 8;
    if (flags || (descriptor & 0xfe000000U) || !type || type >= 0xfc ||
        type == 0x0e || type == 0x26 || type == 0x3e ||
        (sub ? type != 0x16 || (parameter & 0x8000U) : type >= 0x16 && type <= 0x18))
        return UNSUPPORTED;
    if (!sub && length > CHUNK) return BAD_ARGUMENT;
    void *lock = ptr(o, 0x38);
    if (!lock || !ptr(o, 0x10)) return NOT_READY;
    st_i32 error = sep_transfer_lock(lock, 10000);
    if (error) return error;
    if (__atomic_load_n(quarantine(o), __ATOMIC_ACQUIRE)) { sep_transfer_unlock(lock); return OFFLINE; }
    if (!sep_transfer_get_endpoint(o) || !ptr(o, 0x50) || !ptr(o, 0x68) ||
        *(st_u64 *)((st_u8 *)o + 0x58) < CHUNK || *(st_u64 *)((st_u8 *)o + 0x70) < CHUNK) {
        sep_transfer_unlock(lock); return NOT_READY;
    }
    State *s = state(o);
    sep_transfer_zero(s, 0, sizeof(*s));
    s->data = (st_u8 *)input; s->total = length;
    s->descriptor = descriptor; s->wire = type;
    st_u8 *buffer = ptr(o, 0x50);
    st_u16 count;
    if (sub) {
        st_u64 chunk = minimum(length, CHUNK - 6);
        *(st_u32 *)buffer = length; *(st_u16 *)(buffer + 4) = parameter;
        if (chunk) sep_transfer_copy(buffer + 6, input, chunk);
        s->command = parameter; s->sequence = 1; s->offset = chunk; s->flags = SENDING;
        parameter = 0; count = chunk + 6;
    } else {
        if (length) sep_transfer_copy(buffer, input, length);
        s->flags = DIRECT_REPLY; count = length;
    }
    __atomic_store_n(marker(o), SEP_TRANSFER_OWNER_MAGIC, __ATOMIC_RELEASE);
    error = send(o, type, parameter, count);
    if (!error && phase(s) != COMPLETE) error = sep_transfer_wait(ptr(o, 0x10), 10000);
    if (phase(s) == COMPLETE && !error) error = s->status;
    else if (phase(s) != COMPLETE) {
        if (!error) error = OFFLINE; /* A wake is not a reply/completion. */
        __atomic_store_n(quarantine(o), 1, __ATOMIC_RELEASE);
    }
    if (!error && output) {
        *output = s->data; *out_length = s->total;
        s->data = 0; /* detach only a real, complete reply allocation */
    }
    /* Freeze ownership only after the last in-flight receiver has finished.
     * Late packets then have handled=0; quarantine prevents them entering a new
     * shared transaction until the endpoint has actually been disabled. */
    for (;;) {
        st_u32 expected = SEP_TRANSFER_OWNER_MAGIC;
        if (__atomic_compare_exchange_n(marker(o), &expected, SEP_TRANSFER_OWNER_MAGIC | RX_BUSY,
                                        0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) break;
    }
    if ((s->flags & OWNED) && s->data) sep_transfer_free(s->data, s->total);
    sep_transfer_zero(s, 0, sizeof(*s)); /* never clear b8 context owner */
    sep_transfer_zero(ptr(o, 0x50), 0, CHUNK);
    sep_transfer_zero(ptr(o, 0x68), 0, CHUNK);
    __atomic_store_n(marker(o), 0, __ATOMIC_RELEASE);
    sep_transfer_unlock(lock);
    return error;
}

st_i32 sep_transfer_clear_quarantine(void *o) {
    if (!sbio(o) || !ptr(o, 0x38)) return BAD_ARGUMENT;
    void *lock = ptr(o, 0x38);
    st_i32 status = sep_transfer_lock(lock, 10000);
    if (status) return status;
    void *ep = ptr(o, 0x28);
    typedef int (*Enabled)(void *);
    int enabled = ep && (*(Enabled *)(*(st_u8 **)ep + 0xc0))(ep);
    if (enabled || __atomic_load_n(marker(o), __ATOMIC_ACQUIRE)) status = BUSY;
    else __atomic_store_n(quarantine(o), 0, __ATOMIC_RELEASE);
    sep_transfer_unlock(lock);
    return status;
}

st_i32 sep_transfer_transact_wire_iomd(void *o, st_u32 descriptor, const st_u8 *input, st_u64 length,
                                      void *iomd, st_u32 *written, st_u32 flags) {
    if (written) *written = 0;
    if (!iomd) return BAD_ARGUMENT;
    st_u8 *output = 0;
    st_u64 received = 0;
    st_i32 status = sep_transfer_transact_wire(o, descriptor, input, length, &output, &received, flags);
    if (!status && received) {
        typedef st_u64 (*Length)(void *);
        typedef st_u64 (*Write)(void *, st_u64, const void *, st_u64);
        Length capacity = *(Length *)(*(st_u8 **)iomd + 0xb0);
        Write write = *(Write *)(*(st_u8 **)iomd + 0xd0);
        st_u64 count = received <= capacity(iomd) ? write(iomd, 0, output, received) : 0;
        if (written) *written = count;
        if (count != received) status = BAD_ARGUMENT;
    }
    if (output) sep_transfer_free(output, received);
    return status;
}
