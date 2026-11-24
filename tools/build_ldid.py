#!/usr/bin/env python3
"""Build a local Linux ldid for codesign-compatible ad-hoc signing."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "tools" / "ldid"
BIN = REPO / "tools" / "vendor" / "linux" / platform.machine() / "ldid"
STAMP = BIN.with_name(BIN.name + ".version")
URL = "https://github.com/ProcursusTeam/ldid.git"
# Pinned so Mach-O signature layout and flags handling do not change silently.
COMMIT = "18255c55405ab1702d8677bf42018eadc76e0b87"
PATCH_MARKER = "n56-linkedit-payload-v2"


def run(*args, cwd=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def patch_source():
    """Keep linkedit payloads that live after LC_SYMTAB's string table.

    Stock ldid trims the signed code limit to stroff + strsize.  The Health
    repair rebuild appends fresh dyld rebase/bind/export blobs after that
    table inside __LINKEDIT, so both signing and --remove-signature truncated
    them and broke LC_DYLD_INFO_ONLY.  Use the real non-signature payload end
    as a lower bound for the code limit instead.
    """
    path = SRC / "ldid.cpp"
    text = path.read_text()
    if PATCH_MARKER in text:
        return

    old = """        struct linkedit_data_command *signature(NULL);
        struct symtab_command *symtab(NULL);
"""
    new = """        struct linkedit_data_command *signature(NULL);
        struct symtab_command *symtab(NULL);
        uint64_t linkedit_end(0); // n56-linkedit-payload-v2
        uint64_t payload_end(0); // n56-linkedit-payload-v2
        auto note_data = [&](uint32_t offset, uint32_t length) {
            auto end(uint64_t(mach_header.Swap(offset)) + mach_header.Swap(length));
            if (payload_end < end)
                payload_end = end;
        };
"""
    assert text.count(old) == 1, "ldid Allocate declarations changed"
    text = text.replace(old, new)

    old = """            else if (flag_H == false) {
"""
    new = """            else if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
                // n56-linkedit-payload-v2: unsigned slices may have payloads
                // that no load command describes; __LINKEDIT covers them.
                if (cmd == LC_SEGMENT) {
                    auto segment(reinterpret_cast<const struct segment_command *>(load_command));
                    if (strncmp(segment->segname, "__LINKEDIT", 16) == 0) {
                        auto end(uint64_t(mach_header.Swap(segment->fileoff)) +
                                 mach_header.Swap(segment->filesize));
                        if (linkedit_end < end)
                            linkedit_end = end;
                    }
                } else {
                    auto segment(reinterpret_cast<const struct segment_command_64 *>(load_command));
                    if (strncmp(segment->segname, "__LINKEDIT", 16) == 0) {
                        auto end(mach_header.Swap(segment->fileoff) +
                                 mach_header.Swap(segment->filesize));
                        if (linkedit_end < end)
                            linkedit_end = end;
                    }
                }
            }
            else if (cmd == 0x22 || cmd == 0x80000022) {
                // LC_DYLD_INFO / LC_DYLD_INFO_ONLY: every offset/size pair.
                auto info(reinterpret_cast<const uint8_t *>(load_command));
                for (size_t field(8); field != 48; field += 8)
                    note_data(*reinterpret_cast<const uint32_t *>(info + field),
                              *reinterpret_cast<const uint32_t *>(info + field + 4));
            }
            else if (cmd == 0x26 || cmd == 0x29 || cmd == 0x2b || cmd == 0x2e ||
                     cmd == 0x36 || cmd == 0x80000033 || cmd == 0x80000034) {
                // LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS,
                // LC_LINKER_OPTIMIZATION_HINT, LC_ATOM_INFO, and the modern
                // dyld trie/fixup commands all use linkedit_data_command.
                auto data(reinterpret_cast<const struct linkedit_data_command *>(load_command));
                note_data(data->dataoff, data->datasize);
            }
            else if (flag_H == false) {
"""
    assert text.count(old) == 1, "ldid load-command loop changed"
    text = text.replace(old, new)

    old = """        size = (size + 15) & ~(15);
"""
    new = """        // n56-linkedit-payload-v2: LC_SYMTAB's string table is not the end
        // of __LINKEDIT in rebuilt libraries.  Keep every non-signature
        // payload; for unsigned slices __LINKEDIT is the conservative bound.
        if (signature == NULL && linkedit_end > payload_end) {
            _assert(linkedit_end <= mach_header.GetSize());
            payload_end = linkedit_end;
        }
        if (payload_end > size) {
            _assert(payload_end <= mach_header.GetSize());
            size = payload_end;
        }

        size = (size + 15) & ~(15);
"""
    assert text.count(old) == 1, "ldid code-limit calculation changed"
    text = text.replace(old, new)

    path.write_text(text)


def build(force=False):
    expected = f"{COMMIT}:{PATCH_MARKER}\n"
    current = STAMP.read_text() if STAMP.is_file() else None
    if BIN.is_file() and current == expected and not force:
        print("ldid already built:", BIN)
        return BIN

    for tool in ("git", "make", "c++", "pkg-config"):
        if not shutil.which(tool):
            raise SystemExit(f"missing required tool: {tool}")

    try:
        subprocess.run(["pkg-config", "--exists", "libplist-2.0"], check=True)
        subprocess.run(["pkg-config", "--exists", "openssl"], check=True)
    except subprocess.CalledProcessError:
        raise SystemExit("ldid needs libplist-2.0 and openssl development files")

    if not (SRC / ".git").exists():
        if SRC.exists():
            shutil.rmtree(SRC)
        run("git", "clone", "--filter=blob:none", "--no-checkout", URL, SRC)
    run("git", "fetch", "--depth", "1", "origin", COMMIT, cwd=SRC)
    run("git", "checkout", "--detach", COMMIT, cwd=SRC)
    patch_source()
    run("make", "-C", SRC, "-j", str(os.cpu_count() or 2))

    BIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SRC / "ldid", BIN)
    BIN.chmod(0o755)
    STAMP.write_text(expected)
    print("ldid ready:", BIN)
    return BIN


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="rebuild even if the binary exists")
    build(force=parser.parse_args().force)
