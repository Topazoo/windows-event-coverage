"""Root-relative, no-symlink manifest verification using POSIX directory descriptors."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

from .common import EvidenceError, decode_text, envelope, issue, read_bytes, strict_json

RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", re.I)


def manifest_entries(obj):
    if not isinstance(obj, dict) or set(obj) != {"schema_version", "files"} or type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        raise EvidenceError("Expected manifest schema_version 1 and files only")
    rows = obj["files"]
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise EvidenceError("Manifest requires 1 to 10000 files")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}:
            raise EvidenceError("Invalid manifest entry schema")
        name = row["path"]
        if not isinstance(name, str) or len(name) > 4096 or any(c in name for c in ("\\", ":", "\x00")):
            raise EvidenceError("Invalid portable relative manifest path")
        parts = name.split("/")
        if any(part in ("", ".", "..") or part.endswith((".", " ")) or RESERVED.match(part) or
               any(ord(c) < 32 or c in '<>"|?*' for c in part) for part in parts):
            raise EvidenceError("Unsafe manifest path")
        if name.casefold() in seen:
            raise EvidenceError("Duplicate/case-colliding manifest path")
        seen.add(name.casefold())
        if type(row["size"]) is not int or row["size"] < 0 or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", row["sha256"]):
            raise EvidenceError("Invalid size or SHA256")
    return rows


def secure_root(root):
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise EvidenceError("Secure manifest verification requires POSIX directory descriptors; use WSL/Linux")
    # Do not resolve symlinks: open every component from filesystem root with NOFOLLOW.
    path = Path(root).absolute()
    if ".." in path.parts:
        raise EvidenceError("Parent traversal in root path")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_relative(root_fd, name):
    fd = os.dup(root_fd)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)


def validate_manifest(path, root, *, max_bytes=128 * 1024 * 1024):
    if type(max_bytes) is not int or max_bytes < 0:
        raise EvidenceError("Invalid manifest byte budget")
    rows = manifest_entries(strict_json(decode_text(read_bytes(path, 4 * 1024 * 1024))))
    if sum(row["size"] for row in rows) > max_bytes:
        raise EvidenceError("Manifest byte budget exceeded")
    root_fd = secure_root(root)
    records, issues = [], []
    try:
        for index, row in enumerate(rows):
            record = {"path": row["path"], "status": "failed"}
            try:
                fd = open_relative(root_fd, row["path"])
                with os.fdopen(fd, "rb") as source:
                    before = os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise EvidenceError("not_regular_file")
                    if before.st_size != row["size"]:
                        raise EvidenceError("size_mismatch")
                    digest, count = hashlib.sha256(), 0
                    while True:
                        chunk = source.read(min(1024 * 1024, row["size"] - count + 1))
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > row["size"]:
                            raise EvidenceError("file_grew_during_hash")
                        digest.update(chunk)
                    after = os.fstat(source.fileno())
                    attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                    if count != row["size"] or any(getattr(before, a) != getattr(after, a) for a in attributes):
                        raise EvidenceError("file_changed_during_hash")
                    if digest.hexdigest() != row["sha256"].lower():
                        raise EvidenceError("hash_mismatch")
                    record.update(status="verified", size=count, sha256=digest.hexdigest())
            except EvidenceError as exc:
                record["reason"] = str(exc)
                issues.append(issue(str(exc), index))
            except OSError:
                record["reason"] = "missing_denied_or_unsafe_path"
                issues.append(issue("missing_denied_or_unsafe_path", index))
            records.append(record)
    finally:
        os.close(root_fd)
    return envelope("manifest", records, issues,
                    coverage_claim="Listed file bytes only; no origin authentication, unlisted-file completeness or historical-state claim")
