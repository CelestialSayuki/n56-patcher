"""19H422 SEP bridge: endpoint/RPC/credential/SSE, Data controls and shared transfer. Offline only."""
import copy
import hashlib
import json
from pathlib import Path

from . import sep_credential, sep_endpoint, sep_rpc, sep_sse
from .sep_contract import interface

PENDING = [
    "ART/ACM command-body compatibility beyond the SCRD transport (not runtime-validated)",
    "APFS media-key tag dispatch, class-M migration, locker and volume-cookie controls",
    "AppleSEPGenericTransfer changes and remaining SKS encoder versions/operations",
    "encrypted Data keybag provisioning, boot jobs and TrustCache integration",
    "on-device boot, SEP wake, media/file-key roundtrip and failure-path validation",
    "Touch ID/Mesa notification/message bridge (SBIO is reserved, not published)",
]


def build(kernel, work):
    """Patch an already prepared classic J96 KC; never run KPF or visit a device."""
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    report = dict(stage="sep-first", input_sha256=hashlib.sha256(kernel.data).hexdigest(),
                  interface=interface(), encrypted_ready=False, pending=PENDING)
    current = copy.copy(kernel)
    for name, adapter in (("rpc", sep_rpc.adapt), ("endpoint", sep_endpoint.adapt),
                          ("credential", sep_credential.adapt), ("sse", sep_sse.adapt)):
        args = (current, work) if name in ("rpc", "endpoint") else (current,)
        data, report[name] = adapter(*args)
        current = copy.copy(current)
        current.data = bytes(data)
    from .sep_verify import verify
    report["verification"] = verify(kernel, current, report, work)
    report["stage_one_output_sha256"] = hashlib.sha256(current.data).hexdigest()
    # Keep the stage-one verifier scoped to its own bytes. Subsequent leaves
    # validate/report their changes independently before Touch ID publishes SBIO.
    from . import sep_data
    data, report["data_control"] = sep_data.adapt(current, work / "data-control")
    current = copy.copy(current)
    current.data = bytes(data)
    from . import sep_transfer
    data, report["transfer"] = sep_transfer.adapt(current, work / "transfer")
    report["transfer"]["validation"] = sep_transfer.verify(current, data, report["transfer"])
    current = copy.copy(current)
    current.data = bytes(data)
    report["stage"] = "sep-third"
    report["pending"] = [item for item in report["pending"]
                         if not item.startswith("APFS media-key tag dispatch")]
    report["output_sha256"] = hashlib.sha256(current.data).hexdigest()
    output = work / "kc.sep-first.raw"
    output.write_bytes(current.data)
    (work / "sep-first.json").write_text(json.dumps(report, indent=2) + "\n")
    (work / "sep-interface.json").write_text(json.dumps(report["interface"], indent=2) + "\n")
    return output, report
