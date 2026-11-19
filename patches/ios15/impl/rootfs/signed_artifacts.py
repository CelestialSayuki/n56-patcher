"""Read-only validation of completed-package helpers; never compile or reseal."""
import hashlib
from pathlib import Path
import subprocess

from core.context import REPO
from core.trustcache import TrustCache


def validate_helper(record, sources=None):
    path = Path(record.get('path') or '')
    if (not path.is_file() or path.is_symlink() or record.get('signed') is not True or
            hashlib.sha256(path.read_bytes()).hexdigest() != record.get('sha256')):
        raise ValueError('completed signed helper changed/missing: ' + str(path))
    for relative, expected in (sources or record.get('sources', {})).items():
        source = Path(REPO) / relative
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError('completed helper source changed; explicit offline rebuild required: ' + relative)
    subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True, capture_output=True)
    digest, kind = TrustCache._cdhash_any(str(path))
    if record.get('cdhash') != digest.hex() or record.get('hash_type') != kind:
        raise ValueError('completed helper CodeDirectory differs from receipt: ' + str(path))
    return record
