# Third-Party Notices

HexGraph is licensed under AGPL-3.0-or-later (see [LICENSE](LICENSE)). It relies on a number of
third-party tools and libraries, each owned by its respective authors and distributed under its own
license. They are listed below for reference.

## Why this is consistent with AGPL-3.0

HexGraph does not statically link or fold the source of the binary-analysis, fuzzing, extraction, or
rehosting tools listed here into its own program. It invokes them as separate processes, and the vast
majority of those run inside disposable Docker containers (the sandbox, fuzz, build, and rehosting
images) that are built and run at your discretion. That makes this "mere aggregation" of independent
programs, whether on a distribution medium or at run time, rather than a combined work. Each tool runs
under, and remains governed by, its own license, and HexGraph's own code remains AGPL-3.0-or-later.

The license identifiers below are best-effort, and are offered for convenience. For the authoritative,
current license text, always consult each project upstream.

---

## Sandboxed analysis & extraction tools (run as separate processes, in containers)

These are installed into, and invoked from, the HexGraph sandbox, fuzz, build, and rehosting container
images. None of them is linked into the HexGraph host process.

| Tool | Upstream | License (best-effort) |
| --- | --- | --- |
| **radare2** (default decompiler/disassembler) | https://github.com/radareorg/radare2 | LGPL-3.0 (with permissive exceptions; see upstream) |
| **AFL++** (coverage-guided fuzzer; QEMU/FRIDA modes) | https://github.com/AFLplusplus/AFLplusplus | Apache-2.0 (bundles components under other licenses; see upstream) |
| **LLVM / Clang** (incl. **libFuzzer**, SanitizerCoverage, ASan, llvm-symbolizer, llvm-cov) | https://llvm.org | Apache-2.0 WITH LLVM-exception |
| **GCC / binutils / libc6-dev** (build toolchain) | https://gcc.gnu.org , https://www.gnu.org/software/binutils/ | GPL-3.0+ / GPL-3.0+ (runtime libs carry the GCC Runtime Library Exception) |
| **boofuzz** (network/protocol fuzzer) | https://github.com/jtpereyda/boofuzz | GPL-2.0 |
| **preeny / desock.so** (socket-to-stdin shim for desock fuzzing) | https://github.com/zardus/preeny | BSD-2-Clause |
| **Ghidra** (opt-in decompiler; `WITH_GHIDRA=1`) | https://github.com/NationalSecurityAgency/ghidra | Apache-2.0 |
| **FirmAE** (firmware rehosting; opt-in) | https://github.com/pr0v3rbs/FirmAE | MIT (bundles firmadyne + QEMU kernels under their own licenses; see upstream) |
| **QEMU** (full-system + user-mode emulation; qemu-system-*, qemu-user) | https://www.qemu.org | GPL-2.0 (with components under LGPL/BSD; see upstream) |
| **binwalk** (firmware extraction driver) | https://github.com/ReFirmLabs/binwalk | MIT |
| **sasquatch** (patched unsquashfs for vendor/LZMA squashfs) | https://github.com/onekey-sec/sasquatch | GPL-2.0 |
| **squashfs-tools** (unsquashfs) | https://github.com/plougher/squashfs-tools | GPL-2.0+ |
| **The Sleuth Kit** (`mmls`, `tsk_recover` — disk-image extraction) | https://github.com/sleuthkit/sleuthkit | Multiple: IBM Public License / CPL / GPL (per component; see upstream) |
| **jefferson** (JFFS2 extraction) | https://github.com/onekey-sec/jefferson | MIT |
| **ubi_reader** (UBIFS extraction) | https://github.com/onekey-sec/ubi_reader | GPL-3.0 |
| **cramfsswap / cramfs tools** | Debian package | GPL-2.0+ |
| **cpio** | https://www.gnu.org/software/cpio/ | GPL-3.0+ |
| **p7zip** | https://p7zip.sourceforge.net | LGPL-2.1+ (with unRAR restriction; see upstream) |
| **python-lzo / lzo, lzma, lz4, zstd libraries** | various | GPL-2.0+ / various (see upstream) |
| **file / libmagic** | https://www.darwinsys.com/file/ | BSD-2-Clause-style (see upstream) |
| **GDB** (crash triage in fuzz image) | https://www.gnu.org/software/gdb/ | GPL-3.0+ |

### Python libraries used inside the sandbox probes (container only)

| Library | Upstream | License (best-effort) |
| --- | --- | --- |
| **pyelftools** | https://github.com/eliben/pyelftools | Public Domain (Unlicense) |
| **python-magic** | https://github.com/ahupp/python-magic | MIT |
| **r2pipe** | https://github.com/radareorg/radare2-r2pipe | LGPL-3.0 / MIT (see upstream) |
| **paramiko** (SSH for remote-device tier) | https://github.com/paramiko/paramiko | LGPL-2.1+ |
| **afl-cov** | https://github.com/vanhauser-thc/afl-cov | GPL-2.0 |
| **cstruct** (rehosting image) | https://github.com/andreax79/python-cstruct | MIT |
| **yara-python** (YARA pattern matcher; opt-in `features.yara`) | https://github.com/VirusTotal/yara-python | Apache-2.0 (bundles libyara, BSD-3-Clause) |

---

## Host-side Python dependencies (the HexGraph application)

These are installed into the HexGraph Python environment. They are independent libraries that the
application imports, and each is distributed under its own license.

| Library | Upstream | License (best-effort) |
| --- | --- | --- |
| **Pydantic** | https://github.com/pydantic/pydantic | MIT |
| **jsonschema** | https://github.com/python-jsonschema/jsonschema | MIT |
| **PyYAML** | https://github.com/yaml/pyyaml | MIT |
| **SQLAlchemy** | https://www.sqlalchemy.org | MIT |
| **Alembic** | https://alembic.sqlalchemy.org | MIT |
| **FastAPI** | https://github.com/fastapi/fastapi | MIT |
| **Uvicorn** | https://www.uvicorn.org | BSD-3-Clause |
| **python-multipart** | https://github.com/Kludex/python-multipart | Apache-2.0 |
| **Rich** | https://github.com/Textualize/rich | MIT |
| **questionary** | https://github.com/tmbo/questionary | MIT |
| **anthropic** (BYOK backend, optional) | https://github.com/anthropics/anthropic-sdk-python | MIT |
| **mcp** (Model Context Protocol SDK, optional) | https://github.com/modelcontextprotocol/python-sdk | MIT |
| **httpx** (dev/test) | https://github.com/encode/httpx | BSD-3-Clause |
| **pytest** (dev/test) | https://github.com/pytest-dev/pytest | MIT |

---

## Frontend (SPA) dependencies

The web UI is a React, Vite, and TypeScript single-page app, built to static assets and served over
loopback.

| Library | Upstream | License (best-effort) |
| --- | --- | --- |
| **React / React DOM** | https://github.com/facebook/react | MIT |
| **react-router-dom** | https://github.com/remix-run/react-router | MIT |
| **Cytoscape.js** (+ cytoscape-dagre, cytoscape-edgehandles) | https://github.com/cytoscape/cytoscape.js | MIT |
| **highlight.js** | https://github.com/highlightjs/highlight.js | BSD-3-Clause |
| **Vite** | https://github.com/vitejs/vite | MIT |
| **TypeScript** | https://github.com/microsoft/TypeScript | Apache-2.0 |
| **@vitejs/plugin-react** | https://github.com/vitejs/vite-plugin-react | MIT |

---

## Container base images

The sandbox, fuzz, and build images derive from Debian (`debian:bookworm-slim`), and the rehosting
images derive from Ubuntu (`ubuntu:20.04` and `ubuntu:22.04`). These base images themselves aggregate
many independent packages under their respective licenses, predominantly GPL, LGPL, BSD, and MIT. For
the authoritative package licensing, see the Debian and Ubuntu projects.

---

*This list is maintained on a best-effort basis and may lag behind the actual dependency set. For the
precise, current set of dependencies and versions, see [`pyproject.toml`](pyproject.toml),
[`frontend/package.json`](frontend/package.json), and the `Dockerfile.*` and `docker/**/Dockerfile`
build files. When in doubt, the upstream project's own license text is the authority.*
