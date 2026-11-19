"""J96 19H422 / XNU21 <-> N56 16H88 SEP contract (unslid addresses).

This is the interface for later clients, including Touch ID.  SBIO is reserved,
not published/enabled by this stage.  RPC names retain the historical encoder
names: file_unwrap is SKS 16/new_key; file_op is SKS 9/unwrap/rewrap.
"""
from types import MappingProxyType

BUILD = "19H422"
ENDPOINTS = MappingProxyType(dict(log=1, arts=2, artr=3, sbio=8, scrd=10, sse=12, sks=0x12))
SERVICES = ("log", "artr", "arts", "scrd", "sse")
SERVICE_TAGS = MappingProxyType(dict(log=0x6c6f6720, artr=0x61727472,
                                   arts=0x61727473, scrd=0x73637264,
                                   sse=0x73736520, sbio=0x7362696f))
RPC_OPERATIONS = MappingProxyType(dict(file_op=9, file_wrap=15, file_unwrap=16,
                                     media_create=49, media_unwrap=50))
REQUEST_VERSION = 0
SKS_BUFFER_SIZE = 0x4000
SKS_ALIGNMENT = 0x1000
CREDENTIAL_REQUEST = 1
APP_BUFFER_SIZE = 0x1000
SERVICE_RECORD_SIZE = 12

# Checked against native load/store instructions, not the iOS 14 layout.
FIELDS = MappingProxyType(dict(
    sks_input=0x140, sks_output=0x148, sks_endpoint=0x150, sks_reply=0x158,
    manager_transport=0x88, manager_state=0xcc, manager_wake=0x168,
    manager_page_size=0x17c,
    # IOSlaveProcessor grew in XNU21: AppleA7IOP MMIO was 0xa8 on 14!
    transport_mmio=0x100, mailbox_status=0x1008, mailbox_send=0x1010,
    credential_endpoint=0x130, credential_input=0x138, credential_output=0x140,
))
VTABLE = MappingProxyType(dict(manager_endpoint=0x550, manager_allocate=0x558,
    manager_register=0x490, sks_workloop=0x378, workloop_add=0xa0,
    endpoint_start=0xb0, endpoint_input=0x100, endpoint_output=0x108))
V0 = MappingProxyType(dict(media_create=0xfffffff0065fe4ac,
    media_unwrap=0xfffffff0065fe96c, file_op=0xfffffff0065f966c,
    file_wrap=0xfffffff0065fa2ec, file_unwrap=0xfffffff0065fa8d8))
ENCODERS = MappingProxyType(dict(media_create_v1=0xfffffff0065fe704,
    media_unwrap_v1=0xfffffff0065feb60, file_op_v1=0xfffffff0065f9898,
    file_wrap_v1=0xfffffff0065fa4bc, file_unwrap_v1=0xfffffff0065fab9c,
    file_op_v2=0xfffffff0065f9ac8, file_wrap_v2=0xfffffff0065fa6a8,
    file_unwrap_v2=0xfffffff0065fae6c))
SKS_INIT = 0xfffffff0065eecfc
CALLS = MappingProxyType(dict(sks_enabled=0xfffffff0065eead4,
    sks_manager=0xfffffff0065eebf4, sks_protocol=0xfffffff0065ef214,
    sks_input_alloc_failed=0xfffffff006612588,
    sks_input_bind_failed=0xfffffff006612604,
    sks_output_alloc_failed=0xfffffff0066125b0,
    sks_output_bind_failed=0xfffffff0066125d8,
    sep_assert_wait=0xfffffff00633bb2c, sep_thread_block=0xfffffff00633bde4,
    sep_thread_wakeup=0xfffffff00633be2c, sep_service_factory=0xfffffff006308224))
SKS_CALLBACK = 0xfffffff0065ef0d8
HOOKS = MappingProxyType(dict(sep_legacy_wake=0xfffffff006322630,
    sep_legacy_irq=0xfffffff006320934, sep_legacy_services=0xfffffff006320468))


def service_record(name, page_shift):
    """Native SEPService descriptor: fourcc, endpoint, in min/max, out min/max.

    Small legacy apps still allocate 4K even on a 16K AP page; a descriptor's
    one-page *limit* need not equal its actual allocation. SBIO limits are only
    exposed for a future opt-in client, never used by the stage-one publisher.
    """
    import struct
    if page_shift not in (12, 14):
        raise ValueError("SEP descriptor page shift must be 12 or 14")
    pages = 4 if page_shift == 12 else 1
    limits = {"log": (0, 0, 0, pages), "arts": (pages,) * 4,
              "artr": (pages,) * 4, "scrd": (1,) * 4, "sse": (1,) * 4,
              "sbio": (0, 0x4b if page_shift == 12 else 0x13,
                       0, 0x4b if page_shift == 12 else 0x13)}
    return struct.pack("<IB4B3x", SERVICE_TAGS[name], ENDPOINTS[name], *limits[name])


def interface():
    """JSON-friendly constants; code addresses in endpoint/RPC reports are dynamic."""
    return dict(api_version=1, build=BUILD, addresses="unslid J96 only", endpoints=dict(ENDPOINTS),
        services=list(SERVICES), reserved_services=["sbio"], fields=dict(FIELDS),
        vtable=dict(VTABLE), rpc_operations=dict(RPC_OPERATIONS),
        request_version=REQUEST_VERSION, service_record_size=SERVICE_RECORD_SIZE,
        sks_buffer_size=SKS_BUFFER_SIZE, alignment=SKS_ALIGNMENT,
        credential_request=CREDENTIAL_REQUEST, app_buffer_size=APP_BUFFER_SIZE,
        rpc_encoders={name: hex(a) for name, a in ENCODERS.items()},
        v0_encoders={name: hex(a) for name, a in V0.items()},
        calls={name: hex(a) for name, a in CALLS.items()},
        hooks={name: hex(a) for name, a in HOOKS.items()},
        sks_callback=hex(SKS_CALLBACK), mailbox_message_size=8)
