"""Apply the N56 D2186 register profile to the iOS 14 D2207 driver."""
import re
import struct

from patches.shared.impl.kc import pmu_d2186 as pmu


def disable_watchdog(kernel, data):
    if pmu.personality_disabled(data, pmu.WD_MARKER):
        return
    segment = next(s for s in kernel.segs if s["name"] == "__PRELINK_INFO")
    start, size = segment["fo"], segment["fs"]
    xml = bytes(data[start:start + size]).rstrip(b"\0")
    marker = b"<key>IOClass</key><string>" + pmu.WD_MARKER + b"</string>"
    entry = xml.index(marker)
    key = b"<key>IOProviderClass</key>"
    value = xml.index(key, entry, entry + 512) + len(key)
    match = re.match(rb'<string IDREF="[0-9]+"\s*/>|<string>AppleD2207PMU</string>', xml[value:])
    if match is None:
        raise ValueError("14.8 watchdog provider 格式不符")
    xml = xml[:value] + b"<string>AppleD2207PMX</string>" + xml[value + match.end():]
    if len(xml) > size:
        raise ValueError("14.8 prelink plist 空间不足")
    data[start:start + size] = xml.ljust(size, b"\0")


def adapt(kernel):
    data = bytearray(kernel.data)
    segments = pmu.parse_segments(data)
    status = [pmu.patch_plist_match(data, False), pmu.patch_ldo_table(data, False)]
    status += pmu.patch_setldo(data, *pmu.locate_setldo_window(data, segments), False)
    status += [pmu.patch_gpio_mapper(data, False), pmu.patch_gpio_levels(data),
               pmu.patch_event_span(data, False)]
    disable_watchdog(kernel, data)
    # The same rail-range instruction also occurs in unrelated iOS 14 drivers.
    driver = kernel.ksegments("com.apple.driver.AppleD2207PMU")
    checked = b"".join(data[kernel.offset(s["vm"]):kernel.offset(s["vm"]) + s["fs"]]
                       for s in driver if s["name"] in ("__TEXT", "__TEXT_EXEC"))
    plist = next(s for s in kernel.segs if s["name"] == "__PRELINK_INFO")
    checked += data[plist["fo"]:plist["fo"] + plist["fs"]]
    pmu.verify(checked, keep_watchdog=False, disable_rtc=False)

    serial = next(s for s in kernel.ksegments("com.apple.driver.AppleSamsungSerial")
                  if s["name"] == "__TEXT_EXEC")
    matches = pmu.find_word_sig(kernel.read(serial["vm"], serial["fs"]), (0x52804e28,))
    if len(matches) != 1:
        raise ValueError("14.8 UART FIFO 入口不唯一")
    address = serial["vm"] + matches[0]
    offsets = ((0, 0x52804e28, 0x52803e28),
               (16, 0x52804c28, 0x52803828),
               (20, 0x52804829, 0x52803829),
               (36, 0x52800e2a, 0x52801fea))
    for delta, before, after in offsets:
        offset = kernel.offset(address + delta)
        if struct.unpack_from("<I", data, offset)[0] != before:
            raise ValueError(f"14.8 UART FIFO 指令不符：{address + delta:#x}")
        struct.pack_into("<I", data, offset, after)
    return data, {"profile": "D2186", "rtc": True, "watchdog": False,
                  "event_bytes": 14, "uart_fifo": hex(address), "changes": status}
