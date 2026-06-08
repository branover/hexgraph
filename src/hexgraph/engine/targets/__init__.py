"""Target acquisition, lifecycle, and attack surfaces. Modules:
- **ingest** — process bytes into a target (firmware unpacks into child targets).
- **unpack** — firmware extraction (squashfs/cpio/disk-image/wrapped-vendor).
- **targets** — the self-referential target tree + lifecycle.
- **filesystem** — browse a firmware target's unpacked rootfs (configs/scripts/keys).
- **surfaces** — register dynamic web/service surfaces as Channel targets.
- **rehost** — boot a firmware under full-system emulation → a live web_app surface.
- **remote** — a live device reached over SSH/telnet (read-only analysis tools).
- **callback_listener** — the bounded local listener for blind-PoC `{{CALLBACK}}` oracles.
"""
