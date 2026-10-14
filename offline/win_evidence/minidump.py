"""Bounds-checked MINIDUMP_MODULE metadata only; no memory streams or executable loading."""
from __future__ import annotations

import os
import struct
from pathlib import Path, PureWindowsPath

from .common import EvidenceError, envelope, issue

MAX_STREAMS = 4096
MAX_MODULES = 4096
MAX_NAME_BYTES = 65536
MAX_READ_BYTES = 8 * 1024 * 1024


def parse_minidump_file(path, *, include_paths=False):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise EvidenceError("Minidump must be an explicit regular file")
    with p.open("rb") as source:
        before = os.fstat(source.fileno())
        size = before.st_size
        consumed = 0
        def bounded(offset, length):
            if offset < 0 or length < 0 or offset > size or length > size - offset:
                raise EvidenceError("Minidump range is outside file bounds")
        def read(offset, length):
            nonlocal consumed
            bounded(offset, length)
            if consumed + length > MAX_READ_BYTES:
                raise EvidenceError("Minidump metadata read budget exceeded")
            source.seek(offset)
            data = source.read(length)
            consumed += len(data)
            if len(data) != length:
                raise EvidenceError("Minidump truncated during read")
            return data
        signature, version, count, directory, _, timestamp, _ = struct.unpack("<IIIIIIQ", read(0, 32))
        if signature != 0x504D444D or version & 0xFFFF != 0xA793:
            raise EvidenceError("Unsupported minidump signature/version")
        if count > MAX_STREAMS:
            raise EvidenceError("Minidump stream count limit exceeded")
        entries = read(directory, count * 12)
        module_stream = None
        for i in range(count):
            kind, length, offset = struct.unpack_from("<III", entries, i * 12)
            bounded(offset, length)
            if kind == 4:
                if module_stream is not None:
                    raise EvidenceError("Duplicate module streams")
                module_stream = (offset, length)
        if module_stream is None:
            return envelope("minidump_modules", [], [issue("module_stream_absent")],
                            file_size_bytes=size, metadata_bytes_read=consumed)
        offset, length = module_stream
        if length < 4:
            raise EvidenceError("Module stream header truncated")
        count = struct.unpack("<I", read(offset, 4))[0]
        if count > MAX_MODULES or 4 + count * 108 > length:
            raise EvidenceError("Invalid module count/stream length")
        table = read(offset + 4, count * 108)
        records, issues = [], []
        for i in range(count):
            base, image_size, checksum, pe_timestamp, name_rva = struct.unpack_from("<QIIII", table, i * 108)
            vs_signature, _, ms, ls = struct.unpack_from("<IIII", table, i * 108 + 24)
            name_size = struct.unpack("<I", read(name_rva, 4))[0]
            if name_size > MAX_NAME_BYTES or name_size % 2:
                raise EvidenceError("Invalid minidump UTF-16 name length")
            try:
                name = read(name_rva + 4, name_size).decode("utf-16-le", errors="strict")
            except UnicodeError as exc:
                raise EvidenceError("Malformed minidump module name") from exc
            if "\x00" in name or not name:
                raise EvidenceError("Empty/NUL-containing module name")
            version_text = None
            if vs_signature == 0xFEEF04BD:
                version_text = f"{ms >> 16}.{ms & 65535}.{ls >> 16}.{ls & 65535}"
            else:
                issues.append(issue("module_version_signature_invalid", i))
            records.append({"module_index": i, "name": name if include_paths else PureWindowsPath(name).name,
                            "base_address": f"0x{base:x}", "image_size": image_size, "checksum": checksum,
                            "recorded_file_version": version_text, "pe_timestamp_raw": pe_timestamp})
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise EvidenceError("Minidump changed during read")
        return envelope("minidump_modules", records, issues, file_size_bytes=size,
                        metadata_bytes_read=consumed, header_timestamp_raw=timestamp,
                        interpretation="Recorded module metadata only; PE timestamps may be reproducible-build values; memory streams not read")
