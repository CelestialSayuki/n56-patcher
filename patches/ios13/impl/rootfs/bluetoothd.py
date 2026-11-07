import hashlib
import json
import os

from core import log


MANIFEST = os.path.join(os.path.dirname(__file__), "bluetoothd-16H88-xpc13.json")


def build_bluetoothd(ctx):
    directory = ctx.wk("bluetooth")
    source = os.path.join(directory, "bluetoothd.16H88")
    output = os.path.join(directory, "bluetoothd.xpc13")
    os.makedirs(directory, exist_ok=True)
    manifest = json.load(open(MANIFEST))
    if os.path.exists(output):
        data = open(output, "rb").read()
        if hashlib.sha256(data).hexdigest() == manifest["output_sha256"]:
            return output
    ctx.verify_device_system(ctx.ssh)
    ctx.ssh.pull_file("/mnt1/usr/sbin/bluetoothd", source)
    data = bytearray(open(source, "rb").read())
    if len(data) != manifest["source_size"] or hashlib.sha256(data).hexdigest() != manifest["source_sha256"]:
        log.die("SystemA bluetoothd 不是 16H88 profile 支持的版本")
    for edit in manifest["patches"]:
        offset = edit["offset"]
        before = bytes.fromhex(edit["before"])
        after = bytes.fromhex(edit["after"])
        if data[offset:offset + len(before)] != before:
            log.die(f"bluetoothd patch before 不匹配: 0x{offset:x}")
        data[offset:offset + len(before)] = after
    if len(data) != manifest["output_size"] or hashlib.sha256(data).hexdigest() != manifest["output_sha256"]:
        log.die("bluetoothd 生成结果不匹配 xpc13 profile")
    with open(output, "wb") as stream:
        stream.write(data)
    os.chmod(output, 0o755)
    return output
