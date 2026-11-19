#define main n56_runtime_main
#include "runtime.c"
#undef main
#include <assert.h>
int main(void) {
    char text[] = "{\"system_slice\":6,\"data_slice\":7,\"system_uuid\":\"00112233-4455-6677-8899-AABBCCDDEEFF\",\"nested\":{\"system_slice\":1}}";
    document d; d.text = text; jsmn_parser parser; jsmn_init(&parser);
    d.count = jsmn_parse(&parser, text, strlen(text), d.tokens, 256);
    assert(d.count > 0 && slice_value(&d, "system_slice") == 6 && slice_value(&d, "data_slice") == 7);
    char id[64]; uint8_t uuid[16];
    assert(!string_value(&d, "system_uuid", id, sizeof(id)) && !normalize_uuid(id, uuid));
    assert(uuid[0] == 0 && uuid[15] == 0xff && normalize_uuid("no-uuid", uuid));
    char duplicate[] = "{\"system_slice\":6,\"system_slice\":1}";
    d.text = duplicate; jsmn_init(&parser); d.count = jsmn_parse(&parser, duplicate, strlen(duplicate), d.tokens, 256);
    assert(slice_value(&d, "system_slice") == -1);
    puts("rootless runtime JSON field/UUID guards passed; no filesystem or device APIs executed");
    return 0;
}
