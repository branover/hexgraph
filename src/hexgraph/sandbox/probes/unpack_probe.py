#!/usr/bin/env python3
"""Unpack a firmware image INSIDE the sandbox.

argv[1] = /artifact (read-only), argv[2] = /out (writable extraction dir).
Extracts squashfs/cpio/etc., then walks the result and emits a JSON manifest of
the regular files found (flagging ELFs). The host copies the ELF children out of
the mounted /out and registers them as child targets. No network, no execution.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


def _run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr)


def _have(tool: str) -> bool:
    return subprocess.run(["which", tool], capture_output=True).returncode == 0


def _squashfs(artifact: str, root: str) -> str:
    """Extract a squashfs. Prefer sasquatch (handles vendor/non-standard LZMA that
    stock unsquashfs rejects); fall back to unsquashfs."""
    if _have("sasquatch"):
        rc, _out = _run(["sasquatch", "-f", "-d", root, artifact])
        if rc == 0 and os.path.isdir(root) and os.listdir(root):
            return "sasquatch"
    _run(["unsquashfs", "-f", "-d", root, artifact])
    return "unsquashfs"


def _extract(artifact: str, out: str) -> tuple[str, str]:
    """Return (method, root_dir). root_dir is where extracted files live.

    Bare filesystems (squashfs/cpio) extract directly; wrapped/real vendor firmware
    (TRX/uImage/vendor header → squashfs/jffs2/ubifs/cramfs, often nested) goes to
    binwalk's RECURSIVE (matryoshka) extraction, which drives sasquatch/jefferson/
    ubi_reader to peel every layer."""
    with open(artifact, "rb") as fh:
        magic = fh.read(6)

    root = os.path.join(out, "root")
    if magic[:4] in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
        return _squashfs(artifact, root), root
    if magic in (b"070701", b"070702", b"070707"):
        os.makedirs(root, exist_ok=True)
        with open(artifact, "rb") as fh:
            subprocess.run(
                ["cpio", "-idmu", "--no-absolute-filenames"],
                stdin=fh, cwd=root, capture_output=True,
            )
        return "cpio", root
    # Wrapped/real firmware: recursive carve+extract of every nested container.
    # -M = matryoshka (recurse into extracted files), -e = extract, -q = quiet.
    rc, _o = _run(["binwalk", "-e", "-M", "-q", "-C", out, artifact])
    if rc != 0:  # older binwalk without -M, or partial — retry non-recursive
        _run(["binwalk", "-e", "-q", "-C", out, artifact])
    return "binwalk", out


def _walk_files(root: str) -> list[dict]:
    files: list[dict] = []
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            abspath = os.path.join(dirpath, name)
            if not os.path.isfile(abspath) or os.path.islink(abspath):
                continue
            try:
                with open(abspath, "rb") as fh:
                    head = fh.read(4)
                size = os.path.getsize(abspath)
            except OSError:
                continue
            files.append(
                {
                    "rel": os.path.relpath(abspath, root),
                    "container_path": abspath,
                    "size": size,
                    "is_elf": head == b"\x7fELF",
                }
            )
    return files


def main() -> int:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: unpack_probe.py <artifact> <outdir>"}))
        return 2
    artifact, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    method, root = _extract(artifact, out)
    files = _walk_files(root)
    print(
        json.dumps(
            {
                "tool": "unpack_probe",
                "method": method,
                "root": root,
                "files": files,
                "elf_count": sum(1 for f in files if f["is_elf"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
