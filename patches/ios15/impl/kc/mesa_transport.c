/* Native 16H88 Mesa mailbox inside the guarded 19H422 GenericTransfer ABI. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef int i32;
typedef short i16;

#ifndef MESA_DATA
#define MESA_DATA __attribute__((section("__TEXT,__text"), aligned(4)))
#endif
#include "mesa_commands.h"

enum { IDLE, DIRECT_REPLY, SENDING, RECEIVING, COMPLETE };
enum { PHASE = 255, OWNED = 256 };
#define BAD_ARGUMENT ((i32)0xe00002c2)
#define UNSUPPORTED ((i32)0xe00002c7)
#define OFFLINE ((i32)0xe00002c9)
#define NO_MEMORY ((i32)0xe00002bd)
#define INVALID_REPLY 22
#define CHUNK 0x1000
#define MAX_TRANSFER 0x4b000
#define COOKIE_CONTEXT 0x80000000U
#define COOKIE_QUERY 0x40000000U

/* 19H422 GT context: +0x80..+0xb7; owner at +0xb8 MUST remain intact.
 * Our state uses only +0x80..+0xaf; constructor/native ABI are fingerprinted. */
typedef struct {
    u8 *data;
    u64 total, offset;
    u16 sequence, command;
#ifndef MESA_COMPACT_STATE
    u32 requested;
#endif
    i32 status;
    u32 flags;
    u32 wire;
#ifndef MESA_COMPACT_STATE
    u32 reserved;
#endif
} Transfer;
#ifdef MESA_COMPACT_STATE
_Static_assert(sizeof(Transfer) == 0x28, "AppleBiometricSEP state size");
#else
_Static_assert(sizeof(Transfer) == 0x30, "GenericTransfer state size");
#endif

extern void *mesa_get_endpoint(void *);
extern i32 mesa_lock(void *, u32);
extern void mesa_unlock(void *);
extern i32 mesa_wait(void *, u32);
extern void mesa_wake(void *);
extern void *mesa_alloc(u64);
extern void mesa_free(void *, u64);
extern void mesa_copy(void *, const void *, u64);
extern void mesa_zero(void *, int, u64);
extern void mesa_log(const char *, ...);
#ifdef MESA_GT_V2
/* Addresses are linked ONLY from a checked GT v2 report, never hardcoded. */
extern i32 mesa_gt_transact_wire(void *, u32, const u8 *, u64, u8 **, u64 *, u32);
extern u64 mesa_gt_receive_dispatch(void *, void *, const u64 *, void *);
#endif

static const char log_format[] MESA_DATA = "Mesa12 cmd=%#x type=%#x ret=%#x in=%lu out=%lu\n";

#ifndef MESA_GT_V2
static void *pointer(void *object, u32 offset) {
    return *(void **)((u8 *)object + offset);
}

static volatile Transfer *transfer(void *object) {
    return (volatile Transfer *)((u8 *)object + 0x80);
}

static u64 minimum(u64 a, u64 b) { return a < b ? a : b; }

static i32 send_packet(void *object, u8 type, u16 parameter, u16 length) {
    void *endpoint = pointer(object, 0x28);
    typedef i32 (*Send)(void *, const u64 *, void *, u32);
    Send send = *(Send *)(*(u8 **)endpoint + 0xe8);
    u64 word = 8 | ((u64)type << 8) | ((u64)parameter << 16) | ((u64)length << 48);
    return send(endpoint, &word, 0, 1);
}

static void complete(void *object, volatile Transfer *state, i32 status) {
    state->status = status;
    state->flags = (state->flags & OWNED) | COMPLETE;
    mesa_wake(pointer(object, 0x10));
}

#endif

static i32 normalize(MesaCommand *command, const u8 **data, u64 *size) {
    const u8 *input = *data;
    u64 length = *size;
    u16 parameter = command->parameter;
    if (command->encoding == ENROLL_PARAMETERS) {
        /* v2 appends template_domain_selector[20]: discriminator u32 + identity[16].
         * Actual 14/15 SBIO consumes the whole selector ONLY when +30 != 0;
         * zero selects the legacy/default domain and does not read +34..43.
         * The normal libBKDM1 producer zeroes this storage even in v2 mode.
         * SBIO 24e7c constructs canonical default domain {1, zero16}, and
         * 24cfc matches the native fingerprint/default class. That explicit
         * default domain also projects to native12's unqualified enroll30.
         * Named/nondefault domains change capacity/domain selection: reject. */
        if (length != 0x44) return BAD_ARGUMENT;
        u32 selector = *(const u32 *)(input + 0x30);
        if (selector) {
            if (selector != 1) return UNSUPPORTED;
            for (u32 i = 0x34; i < 0x44; ++i) if (input[i]) return UNSUPPORTED;
        }
        length = 0x30;
    } else if (command->encoding == MATCH_PARAMETERS) {
        /* This is the short-session union arm, NOT the 20-byte session arm.
         * Both 12/15 read ACM type/length at +0xc/+0x10, data at +0x14.
         * Native type 0x2b consumes input+8, 0x2c bytes. */
        if (length != 0x44) return BAD_ARGUMENT;
        input += 8;
        length = 0x2c;
    } else if (command->encoding == SESSION_PARAMETERS) {
        /* The other union arm is identical in 12 and 15: session[20], ACM[40].
         * Both callers have ALREADY advanced input by 8; do not do so twice. */
        if (length != 0x3c) return BAD_ARGUMENT;
    }
    if (command->encoding == PARAMETER || command->encoding == SESSION) {
        if (length < 4) return BAD_ARGUMENT;
        u32 value = *(const u32 *)input;
        if (value > 0xffff) return BAD_ARGUMENT;
        parameter = value;
        if (command->encoding == SESSION) {
            if (value != 1 && value != 2 && value != 3 && value != 5) return UNSUPPORTED;
            --parameter;
        }
        input += 4;
        length -= 4;
    }
    command->parameter = parameter;
    if (command->encoding != SUBCOMMAND) command->encoding = RAW;
    *data = input;
    *size = length;
    return 0;
}

#ifndef MESA_GT_V2
static i32 request(void *object, volatile Transfer *state, MesaCommand command,
                   const u8 *input, u64 length) {
    u16 parameter = command.parameter;
    state->data = (u8 *)input;
    state->total = length;
    state->wire = command.type;
    u8 *buffer = pointer(object, 0x50);
    if (command.encoding != SUBCOMMAND) {
        if (length > CHUNK) return BAD_ARGUMENT;
        if (length) mesa_copy(buffer, input, length);
        state->flags = DIRECT_REPLY;
        return send_packet(object, command.type, parameter, length);
    }
    u64 chunk = minimum(length, CHUNK - 6);
    *(u32 *)buffer = length;
    *(u16 *)(buffer + 4) = parameter;
    if (chunk) mesa_copy(buffer + 6, input, chunk);
    state->command = parameter;
    state->sequence = 1;
    state->offset = chunk;
    state->flags = SENDING;
    return send_packet(object, 0x16, 0, chunk + 6);
}

static void direct_reply(void *object, volatile Transfer *state, u64 word) {
    i32 status = (i16)(word >> 16);
    u64 length = word >> 48;
    if (length > CHUNK) { complete(object, state, INVALID_REPLY); return; }
    if (status) { complete(object, state, status); return; }
    state->data = 0;
    state->total = length;
    if (length) {
        state->data = mesa_alloc(length);
        if (!state->data) { complete(object, state, NO_MEMORY); return; }
        state->flags |= OWNED;
        mesa_copy(state->data, pointer(object, 0x68), length);
    }
    complete(object, state, 0);
}

static void first_reply(void *object, volatile Transfer *state, u64 word) {
    u64 length = word >> 48;
    u8 *buffer = pointer(object, 0x68);
    if ((state->flags & PHASE) != SENDING || state->offset != state->total ||
        (u16)(word >> 16) || length < 8 || length > CHUNK) {
        complete(object, state, INVALID_REPLY); return;
    }
    u64 total = *(u32 *)buffer;
    u16 command = *(u16 *)(buffer + 4);
    i32 status = *(i16 *)(buffer + 6);
    u64 chunk = length - 8;
    if (command != (u16)(state->command | 0x8000) || total > MAX_TRANSFER ||
        chunk != minimum(total, CHUNK - 8)) {
        complete(object, state, INVALID_REPLY); return;
    }
    if (status) { complete(object, state, status); return; }
    state->data = 0;
    state->total = total;
    state->offset = chunk;
    /* iOS 12 keeps counting from the request chunks (0x8609518). */
    state->flags = RECEIVING;
    if (total) {
        state->data = mesa_alloc(total);
        if (!state->data) { complete(object, state, NO_MEMORY); return; }
        state->flags |= OWNED;
        if (chunk) mesa_copy(state->data, buffer + 8, chunk);
    }
    if (chunk == total) { complete(object, state, 0); return; }
    i32 error = send_packet(object, 0x18, 0, 0);
    if (error) complete(object, state, error);
}

static void receive_chunk(void *object, volatile Transfer *state, u64 word) {
    u64 length = word >> 48;
    u16 sequence = word >> 16;
    if ((state->flags & PHASE) != RECEIVING ||
        sequence != (u16)(state->sequence + 1) ||
        length != minimum(state->total - state->offset, CHUNK)) {
        complete(object, state, INVALID_REPLY); return;
    }
    if (length) mesa_copy(state->data + state->offset, pointer(object, 0x68), length);
    state->offset += length;
    state->sequence = sequence;
    if (state->offset == state->total) { complete(object, state, 0); return; }
    i32 error = send_packet(object, 0x18, 0, 0);
    if (error) complete(object, state, error);
}

static void send_chunk(void *object, volatile Transfer *state, u64 word) {
    if ((state->flags & PHASE) != SENDING || (u16)(word >> 16) ||
        (word >> 48) || state->offset >= state->total) {
        complete(object, state, INVALID_REPLY); return;
    }
    u64 length = minimum(state->total - state->offset, CHUNK);
    if (length) mesa_copy(pointer(object, 0x50), state->data + state->offset, length);
    state->offset += length;
    u16 sequence = state->sequence++;
    i32 error = send_packet(object, 0x17, sequence, length);
    if (error) complete(object, state, error);
}

#endif /* Mesa-local engine: never interpret GT v2 State as Transfer. */

/* IOBiometricFamily expiry callers carry context ID in data (not cookie type).
 * 14/15 0x26 clears unlock token, 0x72 additionally resets retained biometric
 * authorization; native12's existing combined revoke operation is type2c.
 * All three native12 expiry handlers use it for the same events. The native12
 * handler returns WITHOUT a reply on success: do NOT transact/wait or invent an
 * ACK. Return the REAL endpoint enqueue status; receiver still errors on an
 * unexpected error reply. No Mesa-local access to shared GT state/quarantine. */
i32 mesa_send_message(void *object, u32 operation, u32 parameter, u32 data) {
    if (!object) return BAD_ARGUMENT;
    if (operation != 0x26 && operation != 0x72) return UNSUPPORTED;
    if (parameter) return BAD_ARGUMENT;
    /* Native12 receives a signed16 ID. -1 is the all-context sentinel; NEVER
     * turn a positive 65535 or arbitrary modern u32 ID into revoke-all. */
    if ((u32)(i32)(i16)data != data) return UNSUPPORTED;
    /* Native12 non-16/17/18 dispatch resets its chunk context. Serialize this
     * header-only send against GT transactions WITHOUT reading GT State. The
     * proved lock computes a deadline from milliseconds; 0 is nonblocking.
     * This is NOT a nested lock around transact_wire (which owns its lock). */
    void *lock = *(void **)((u8 *)object + 0x38);
    if (!lock) return OFFLINE;
    i32 status = mesa_lock(lock, 0);
    if (status) return status;
    void *endpoint = mesa_get_endpoint(object);
    if (!endpoint) { mesa_unlock(lock); return OFFLINE; }
    typedef i32 (*Send)(void *, const u64 *, void *, u32);
    Send send = *(Send *)(*(u8 **)endpoint + 0xe8);
    u64 word = 8 | (0x2cUL << 8) | ((u64)(u16)data << 16);
    status = send(endpoint, &word, 0, 1);
    mesa_unlock(lock);
    mesa_log(log_format, operation, 0x2c, (u32)status, (u64)data, 0UL);
    return status;
}

i32 mesa_notification(void *object, const u64 *message, void *callback) {
    (void)object;
    if (!message || !callback) return BAD_ARGUMENT;
    u64 word = *message;
    if ((u8)word != 8) return INVALID_REPLY;
    u8 type = word >> 8;
    if (type != 0x0e && type != 0x26 && type != 0x3e) return UNSUPPORTED;
    u8 translated = type == 0x0e ? 1 : (type == 0x3e ? 2 : 3);
    /* Endpoint and all parameter/length/payload bits stay EXACTLY intact. */
    word = (word & ~(0xffUL << 8)) | ((u64)translated << 8);
    typedef i32 (*Notify)(void *, u64);
    Notify notify = *(Notify *)((u8 *)callback + 0x10);
    return notify(callback, word);
}

i32 mesa_receive(void *object, void *context, const u64 *message, void *callback) {
#ifdef MESA_GT_V2
    u64 handled = mesa_gt_receive_dispatch(object, context, message, callback);
    if (handled >> 32) return (i32)handled;
#else
    (void)context;
#endif
    if (!message || !callback) return BAD_ARGUMENT;
    u64 word = *message;
    if ((u8)word != 8) return INVALID_REPLY;
    u8 type = word >> 8;
    if (type == 0x0e || type == 0x26 || type == 0x3e)
        return mesa_notification(object, message, callback);
#ifdef MESA_GT_V2
    /* handled=0 is NOT permission to run the old, differently laid out state
     * machine. The shared engine may have retired/quarantined a late reply.
     * Only the three proved notifications can bypass it; unknown notifications
     * and orphaned packets must fail, without changing marker/state/quarantine. */
    return UNSUPPORTED;
#else
    volatile Transfer *state = transfer(object);
    u32 phase = state->flags & PHASE;
    if (phase == IDLE || phase == COMPLETE) return UNSUPPORTED;
    if (phase == DIRECT_REPLY) {
        if (type != state->wire) { complete(object, state, INVALID_REPLY); return 0; }
        direct_reply(object, state, word);
    } else if (type == 0x16) {
        first_reply(object, state, word);
    } else if (type == 0x17) {
        receive_chunk(object, state, word);
    } else if (type == 0x18) {
        send_chunk(object, state, word);
    } else {
        complete(object, state, INVALID_REPLY);
    }
    return 0;
#endif
}

i32 mesa_transact(void *object, u32 operation, const u8 *input, u64 length,
                  u8 **output, u64 *output_length, u32 flags) {
    if (!object || (output == 0) != (output_length == 0) || (length && !input) || length > MAX_TRANSFER)
        return BAD_ARGUMENT;
    if (output) { *output = 0; *output_length = 0; }
    u32 requested = operation;
    u64 requested_length = length;
    /* The legacy driver starts without the newer initSbioCommunication handshake. */
    if (operation == 0x73) return 0;
    MesaCommand command = { 0, RAW, 0 };
    if (operation < sizeof(commands) / sizeof(commands[0])) command = commands[operation];
    if (flags & COOKIE_CONTEXT) {
        u16 message_type = flags;
        if (message_type > 10 || (flags & 0x3fff0000U)) return BAD_ARGUMENT;
        if (flags & COOKIE_QUERY) command.type = 0x4b;
        else if (operation == 0 || operation == 0x4a || operation == 0x4c ||
                 operation == 0x4e || operation == 0x51 || operation == 0x52 ||
                 operation == 0x77) command.type = 0x4c;
        else if (operation == 0x49 || operation == 0x4b || operation == 0x4d ||
                 operation == 0x4f || operation == 0x53 || operation == 0x76)
            command.type = 0x4d;
        else return UNSUPPORTED;
        /* The 12 send ABI is (u8 type, u16 parameter, opaque body). Preserve
         * all 15-known subtypes 0..10. New 8/9/10 use the same getter/setter/
         * query roles; native SEP refusal is propagated, NEVER fabricated. */
        command.encoding = RAW;
        command.parameter = message_type;
    } else if (flags) {
        /* All checked Mesa callers pass zero native GT flags. Do not silently
         * turn an unproved modern flag (including query without context) into
         * a successful ordinary operation. */
        return UNSUPPORTED;
    }
    if (!command.type) return UNSUPPORTED;
    i32 converted = normalize(&command, &input, &length);
    if (converted) return converted;
#ifdef MESA_GT_V2
    /* Shared engine exclusively owns +80..af/+b0 marker and quarantine +b4.
     * Mesa must NOT lock, zero that state or touch the original owner +b8. */
    u32 descriptor = command.type | ((u32)command.parameter << 8);
    if (command.encoding == SUBCOMMAND) descriptor |= 1U << 24;
    u8 *reply = 0;
    u64 received = 0;
    i32 error = mesa_gt_transact_wire(object, descriptor, input, length,
        output ? &reply : 0, output ? &received : 0, 0);
    if (!error && output) {
        *output = reply;
        *output_length = received;
        reply = 0;
    }
    if (reply) mesa_free(reply, received);
    mesa_log(log_format, requested, command.type, (u32)error, requested_length, received);
    return error;
#else
    void *lock = pointer(object, 0x38);
    i32 error = mesa_lock(lock, 10000);
    if (error) return error;
    if (!mesa_get_endpoint(object) || !pointer(object, 0x50) || !pointer(object, 0x68) ||
        *(u64 *)((u8 *)object + 0x58) < CHUNK ||
        *(u64 *)((u8 *)object + 0x70) < CHUNK) { mesa_unlock(lock); return OFFLINE; }
    volatile Transfer *state = transfer(object);
    mesa_zero((void *)state, 0, sizeof(*state));
#ifndef MESA_COMPACT_STATE
    state->requested = requested;
#endif
    error = request(object, state, command, input, length);
    if (!error && (state->flags & PHASE) != COMPLETE) {
        error = mesa_wait(pointer(object, 0x10), 10000);
    }
    if (!error && (state->flags & PHASE) != COMPLETE) error = OFFLINE;
    if (!error) error = state->status;
    u64 received = 0;
    if (!error && output) {
        received = state->total;
        *output = state->data;
        *output_length = received;
        state->data = 0;
    }
    state->flags = (state->flags & OWNED) | IDLE;
    if ((state->flags & OWNED) && state->data) mesa_free(state->data, state->total);
    mesa_zero((void *)state, 0, sizeof(*state));
    mesa_zero(pointer(object, 0x50), 0, *(u64 *)((u8 *)object + 0x58));
    mesa_zero(pointer(object, 0x68), 0, *(u64 *)((u8 *)object + 0x70));
    mesa_unlock(lock);
    mesa_log(log_format, requested, command.type, (u32)error, requested_length, received);
    return error;
#endif
}

/* 15's Mesa also uses transactToIOMD. Preserve its descriptor/writeBytes ABI;
 * never leave that path speaking the modern GT 0xfc protocol. */
i32 mesa_transact_iomd(void *object, u32 operation, const u8 *input, u64 length,
                      void *descriptor, u32 *written, u32 flags) {
    if (written) *written = 0;
    if (!descriptor) return BAD_ARGUMENT;
    u8 *output = 0;
    u64 received = 0;
    i32 status = mesa_transact(object, operation, input, length, &output, &received, flags);
    if (!status && received) {
        typedef u64 (*Write)(void *, u64, const void *, u64);
        typedef u64 (*Length)(void *);
        Length capacity = *(Length *)(*(u8 **)descriptor + 0xb0);
        Write write = *(Write *)(*(u8 **)descriptor + 0xd0);
        u64 count = received <= capacity(descriptor) ? write(descriptor, 0, output, received) : 0;
        if (written) *written = count;
        if (count != received) status = BAD_ARGUMENT;
    }
    if (output) mesa_free(output, received);
    return status;
}
