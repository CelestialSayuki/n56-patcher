/* Native iOS 12 Mesa mailbox transport inside the iOS 14 GenericTransfer object. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef int i32;
typedef short i16;

#define MESA_DATA __attribute__((section("__TEXT,__text"), aligned(4)))
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

/* The existing GenericTransfer state occupies +0x80..+0xaf on 14.8; +0xb0 retains its owner.
 * iOS 13.7's AppleBiometricSEP state is 0x28 bytes, so its build drops the two unused words. */
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

static const char log_format[] MESA_DATA = "Mesa12 cmd=%#x type=%#x ret=%#x in=%lu out=%lu\n";

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

static i32 request(void *object, volatile Transfer *state, MesaCommand command,
                   const u8 *input, u64 length) {
    u16 parameter = command.parameter;
    if (command.encoding == ENROLL_PARAMETERS) {
        if (length < 0x30) return BAD_ARGUMENT;
        length = 0x30;
    } else if (command.encoding == MATCH_PARAMETERS) {
        if (length < 8 + 0x2c) return BAD_ARGUMENT;
        input += 8;
        length = 0x2c;
    }
    if (command.encoding == PARAMETER || command.encoding == SESSION) {
        if (length < 4) return BAD_ARGUMENT;
        parameter = *(const u16 *)input;
        if (command.encoding == SESSION) {
            if (parameter != 1 && parameter != 2 && parameter != 3 && parameter != 5)
                return UNSUPPORTED;
            --parameter;
        }
        input += 4;
        length -= 4;
    }
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
    if ((state->flags & PHASE) != SENDING || (u16)(word >> 16)) {
        complete(object, state, INVALID_REPLY); return;
    }
    u64 length = minimum(state->total - state->offset, CHUNK);
    if (length) mesa_copy(pointer(object, 0x50), state->data + state->offset, length);
    state->offset += length;
    u16 sequence = state->sequence++;
    i32 error = send_packet(object, 0x17, sequence, length);
    if (error) complete(object, state, error);
}

void mesa_receive(void *object, void *context, const u64 *message, void *callback) {
    (void)context;
    u64 word = *message;
    u8 type = word >> 8;
    if (type == 0x0e || type == 0x26 || type == 0x3e) {
        u8 translated = type == 0x0e ? 1 : (type == 0x3e ? 2 : 3);
        word = (word & ~(0xffUL << 8)) | ((u64)translated << 8);
        typedef void (*Notify)(void *, u64);
        Notify notify = *(Notify *)((u8 *)callback + 0x10);
        notify(callback, word);
        return;
    }
    volatile Transfer *state = transfer(object);
    u32 phase = state->flags & PHASE;
    if (phase == IDLE || phase == COMPLETE) return;
    if (phase == DIRECT_REPLY) {
        if (type != state->wire) { complete(object, state, INVALID_REPLY); return; }
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
}

i32 mesa_transact(void *object, u32 operation, const u8 *input, u64 length,
                  u8 **output, u64 *output_length, u32 flags) {
    if ((output == 0) != (output_length == 0) || (length && !input) || length > MAX_TRANSFER)
        return BAD_ARGUMENT;
    if (output) { *output = 0; *output_length = 0; }
    /* The legacy driver starts without the newer initSbioCommunication handshake. */
    if (operation == 0x73) return 0;
    MesaCommand command = { 0, RAW, 0 };
    if (operation < sizeof(commands) / sizeof(commands[0])) command = commands[operation];
    if (flags & COOKIE_CONTEXT) {
        u16 message_type = flags;
        if (message_type > 7) return UNSUPPORTED;
        if (flags & COOKIE_QUERY) command.type = 0x4b;
        else if (!operation) command.type = 0x4c;
        command.encoding = RAW;
        command.parameter = message_type;
    }
    if (!command.type) return UNSUPPORTED;
    void *lock = pointer(object, 0x38);
    i32 error = mesa_lock(lock, 10000);
    if (error) return error;
    if (!mesa_get_endpoint(object)) { mesa_unlock(lock); return OFFLINE; }
    volatile Transfer *state = transfer(object);
    mesa_zero((void *)state, 0, sizeof(*state));
#ifndef MESA_COMPACT_STATE
    state->requested = operation;
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
    mesa_log(log_format, operation, command.type, (u32)error, length, received);
    return error;
}
