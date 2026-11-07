"""Remove the two USB experiment arguments from a decoded N56 iBEC."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT_ARG = b'rd=disk0s1s4 '
USB_ARGS = {'AppleEmbeddedUSBArbitrator-force-usbdevice',
            'AppleEmbeddedUSBArbitrator-debug'}


def bootargs(data):
    if data.count(ROOT_ARG) != 1:
        raise ValueError('expected exactly one N56 SystemB boot-args string')
    start = data.index(ROOT_ARG)
    end = data.index(b'\x00', start)
    return start, end, data[start:end].decode('ascii')


def clean(data):
    start, end, before = bootargs(data)
    tokens = before.split()
    removed = [token for token in tokens if token.partition('=')[0] in USB_ARGS]
    after = ' '.join(token for token in tokens if token.partition('=')[0] not in USB_ARGS)
    if not removed:
        after = before
    replacement = after.encode('ascii')
    result = data[:start] + replacement + bytes(end - start - len(replacement)) + data[end:]
    verify(result)
    return result, dict(before=before, after=after, removed=removed, start=start, end=end,
                        source_sha256=hashlib.sha256(data).hexdigest(),
                        cleaned_sha256=hashlib.sha256(result).hexdigest())


def verify(data):
    args = bootargs(data)[2]
    if any(token.partition('=')[0] in USB_ARGS for token in args.split()):
        raise ValueError('iBEC still contains a USB override; run sn2400_port/prepare.sh')
    return args


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if args.verify:
        if args.output or args.report:
            parser.error('--verify does not accept an output or report')
        print('Verified native USB boot-args: ' + verify(args.input.read_bytes()))
    else:
        if args.output is None:
            parser.error('an output path is required when cleaning')
        result, report = clean(args.input.read_bytes())
        args.output.write_bytes(result)
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Removed USB arguments: ' + ', '.join(report['removed']))
        print('Boot-args: ' + report['after'])
