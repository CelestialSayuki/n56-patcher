"""Report-derived Mesa ABI handoff written next to kc.touchid.raw."""

GT_SIGNATURES = {
    'sep_transfer_transact_wire': 'i32 (void *object, u32 descriptor, const u8 *input, u64 length, u8 **output, u64 *output_length, u32 flags)',
    'sep_transfer_transact_wire_iomd': 'i32 (void *object, u32 descriptor, const u8 *input, u64 length, void *iomd, u32 *written, u32 flags)',
    'sep_transfer_receive_dispatch': 'u64 (void *object, void *context, const u64 *message, void *callback)',
    'sep_transfer_clear_quarantine': 'i32 (void *object)',
}
MESA_SIGNATURES = {
    'mesa_transact': GT_SIGNATURES['sep_transfer_transact_wire'].replace('descriptor', 'operation'),
    'mesa_transact_iomd': GT_SIGNATURES['sep_transfer_transact_wire_iomd'].replace('descriptor', 'operation'),
    'mesa_receive': 'i32 (void *object, void *context, const u64 *message, void *callback)',
    'mesa_notification': 'i32 (void *object, const u64 *message, void *callback)',
    'mesa_send_message': 'i32 (void *object, u32 operation, u32 parameter, u32 data)',
}


def interface(report):
    gt = report.get('gt_v2')
    return dict(api_version=2, build=report['build'], touchid_ready=False,
        payload=dict(address=report['cave'], size=report['code_bytes'],
                     overwritten_span=report['code_write_bytes'],
                     zeroed_tail=report['code_write_bytes'] - report['code_bytes'],
                     sha256=report['payload_sha256']),
        mesa_exports=report['entries'], mesa_signatures=MESA_SIGNATURES,
        receive_dispatch=report['receive_dispatch'], receive_native_resume=report['receive_resume'],
        hooks=report['hooks'], actual_hook_edits=report['writes'],
        canonical_installed_words=report['stock_writes'],
        gt_v2_exports=gt['exports'] if gt else None, gt_v2_signatures=GT_SIGNATURES,
        descriptor='type | (u16 parameter << 8) | (subchannel ? 1<<24 : 0); direct exports use flags=0, NO bit31',
        receive_result='high32 != 0 means handled; low32 is the actual callback status. handled=0 only permits proved notifications, otherwise UNSUPPORTED',
        ownership='GT owns transfer state; AP-local init reads quarantine under its serializer, never clears state/quarantine; +b8 owner intact',
        quarantine='Mesa never clears quarantine; clear_quarantine ABI unchanged, transport owner must first drain/reset and satisfy its existing idle/lock checks',
        one_way_send=report['one_way_send'], protocol=report['protocol'], legacy_boundaries=report.get('legacy_boundaries',{}), pending=report['pending'],
        input_sha256=report['input_sha256'], output_sha256=report['output_sha256'],
        verification=report['verification'])

