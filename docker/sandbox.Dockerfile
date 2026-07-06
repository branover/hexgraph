# HexGraph analysis sandbox (SPEC §3, §7). One image with the static-analysis
# toolchain. Run ONLY via sandbox/runner.py with --network none + resource caps.
# Build:  docker build -f docker/sandbox.Dockerfile -t hexgraph-sandbox:latest .  (context = repo root)
#         add --build-arg WITH_GHIDRA=1 to include Ghidra headless (large).
FROM debian:bookworm-slim

ARG WITH_GHIDRA=0
# Ghidra release to install when WITH_GHIDRA=1 (large: pulls a JDK + ~400MB Ghidra).
# Ghidra 11.2+ (incl. the 12.x line we ship) requires JDK 21 — JDK 17 is too old and
# analyzeHeadless refuses to launch. bookworm-slim's main repo only ships openjdk-17,
# so we add the Adoptium/Temurin apt repo and install temurin-21-jdk (a slim, reliable
# JDK 21). The WITH_GHIDRA build asserts the installed JDK satisfies Ghidra's documented
# minimum (application.properties `application.java.min`), so a future Ghidra bump that
# needs a newer JDK FAILS the build loudly instead of shipping broken. Bump REQUIRED_JDK
# (below) alongside GHIDRA_VERSION if you move up a line that needs a newer JDK.
ARG GHIDRA_VERSION=12.1
ARG GHIDRA_DATE=20260513
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
# The JDK major version this Ghidra line needs (used by the build-time assertion).
ARG REQUIRED_JDK=21
# radare2 isn't in bookworm-slim's apt sources, so install the upstream .deb.
ARG R2_VERSION=6.1.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        file \
        binutils \
        binwalk \
        squashfs-tools \
        cpio \
        python3 \
        python3-pip \
        python3-dev \
        curl \
        ca-certificates \
        gcc \
        g++ \
        libc6-dev \
        clang \
        libclang-rt-dev \
    && curl -fsSL -o /tmp/radare2.deb \
        "https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2_${R2_VERSION}_amd64.deb" \
    && (dpkg -i /tmp/radare2.deb || apt-get install -fy --no-install-recommends) \
    && rm -f /tmp/radare2.deb \
    && rm -rf /var/lib/apt/lists/*

# Static-analysis Python libs. --break-system-packages: this is a single-purpose
# disposable image, not a shared host.
#
# flare-floss (Phase 5A) is FLOSS — recovers stack/tight/decoded strings a plain
# `strings` pass misses by lightly emulating the decode routines in-process (it vendors
# vivisect). Pinned to a known-good release; it pulls a mostly pure-Python emulation stack
# (vivisect/viv-utils/pefile). Its `binary2strings` dep ships no Linux wheel, so pip builds
# it (a pybind11 C++ extension) from source here — hence `g++` + `python3-dev` (Python.h)
# in the apt list above. The
# floss_probe degrades gracefully to a static-only pass on non-PE/foreign-arch artifacts.
# The sandbox-build CI job asserts the `floss` CLI is present so an image change can't
# silently drop it.
#
# yara-python (Phase 5B) is the YARA matcher used by yara_probe — a project-wide pattern
# sweep over targets + extracted firmware files (embedded creds, known-bad library banners,
# weak-crypto constants, packer signatures). Small, mature; the wheel bundles libyara, so
# no separate apt package is needed. The yara_probe imports `yara` (yara-python) directly,
# so the `yara` CLI is optional — but we assert the module imports in the sandbox-build CI
# job so an image change can't silently drop it. Pinned to a known-good release.
RUN pip3 install --no-cache-dir --break-system-packages \
        pyelftools \
        python-magic \
        r2pipe \
        paramiko \
        flare-floss==3.1.1 \
        yara-python==4.5.1

# Ghidra is opt-in (large; pulls a JDK 21 + the Ghidra distribution). The
# R2Decompiler stays the always-available default; GhidraDecompiler is selected
# only when enabled in Settings. Ghidra lands at $GHIDRA_INSTALL_DIR and is driven
# IN-PROCESS via PyGhidra (jpype), not the analyzeHeadless CLI.
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
# Temurin lands at a versioned path; point JAVA_HOME/PATH at it so PyGhidra's JVM
# (and any `java`) resolve to JDK 21, not some other JVM. Harmless when WITH_GHIDRA=0
# (the path simply won't exist and nothing in the static-only image invokes java).
ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
RUN if [ "$WITH_GHIDRA" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            unzip wget gnupg \
        # Adoptium/Temurin apt repo — the reliable, lean JDK 21 source for bookworm.
        && wget -qO /usr/share/keyrings/adoptium.asc https://packages.adoptium.net/artifactory/api/gpg/key/public \
        && echo "deb [signed-by=/usr/share/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb bookworm main" \
            > /etc/apt/sources.list.d/adoptium.list \
        && apt-get update && apt-get install -y --no-install-recommends temurin-21-jdk \
        && wget -q -O /tmp/ghidra.zip "$GHIDRA_URL" \
        && unzip -q /tmp/ghidra.zip -d /opt \
        && mv /opt/ghidra_* /opt/ghidra \
        && rm -f /tmp/ghidra.zip \
        # Drive Ghidra IN-PROCESS via PyGhidra (CPython 3 over jpype), NOT analyzeHeadless + Jython:
        # the probe (sandbox/probes/ghidra_probe.py) and the resident bridge import `pyghidra` and
        # call the Ghidra Java API directly (each analysis core ports ~1:1 from its former Jython
        # postScript, now in sandbox/probes/pyghidra_lib.py). Ghidra ships the PyGhidra module under
        # Features/PyGhidra — KEEP it (earlier images deleted it to force Jython to own `.py`) and
        # install its Python package so `import pyghidra` works. Prefer the BUNDLED wheel (version-
        # locked to THIS Ghidra) over PyPI so a Ghidra bump can't drift the API; jpype1 (the only
        # native dep) resolves from a prebuilt PyPI wheel (no compiler). --break-system-packages for
        # PEP 668. NO Jython and NO ghidra_bridge/jfx_bridge: the managed bridge is now HexGraph's
        # own stdlib-socket JSON RPC (pyghidra_lib.serve_bridge), and radare2 remains the default
        # decompiler (Ghidra is the opt-in upgrade).
        && PYGHIDRA_WHL="$(ls /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl 2>/dev/null | head -n1)" \
        && if [ -n "$PYGHIDRA_WHL" ]; then \
               echo "Installing bundled PyGhidra wheel: $PYGHIDRA_WHL"; \
               python3 -m pip install --no-cache-dir --break-system-packages "$PYGHIDRA_WHL"; \
           else \
               echo "NOTE: no bundled PyGhidra wheel found; installing pyghidra from PyPI"; \
               python3 -m pip install --no-cache-dir --break-system-packages pyghidra; \
           fi \
        # Fail the build NOW if the module or its Ghidra-side jar is missing (a silent absence would
        # otherwise only surface as a per-call probe error at runtime).
        && python3 -c "import pyghidra" \
        && test -f /opt/ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar \
        # --- Build-time JDK ↔ Ghidra assertion -------------------------------------
        # Fail the build NOW if the installed JDK can't run this Ghidra, so a future
        # version bump cannot ship broken (as it did twice). Cross-check two facts:
        #   1. the JVM on PATH is at least the major we expect (REQUIRED_JDK), and
        #   2. it satisfies Ghidra's own documented minimum (application.java.min in
        #      Ghidra/application.properties), when that field is present.
        && JAVA_MAJOR="$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -n1)" \
        && echo "Detected JDK major: ${JAVA_MAJOR}; required (REQUIRED_JDK): ${REQUIRED_JDK}" \
        && if [ -z "$JAVA_MAJOR" ]; then \
               echo "FATAL: could not determine the installed JDK major version" >&2; exit 1; \
           fi \
        && if [ "$JAVA_MAJOR" -lt "$REQUIRED_JDK" ]; then \
               echo "FATAL: JDK ${JAVA_MAJOR} < required ${REQUIRED_JDK} for Ghidra ${GHIDRA_VERSION}" >&2; exit 1; \
           fi \
        && GHIDRA_MIN="$(sed -n 's/^application\.java\.min=//p' /opt/ghidra/Ghidra/application.properties | head -n1)" \
        && if [ -n "$GHIDRA_MIN" ]; then \
               echo "Ghidra ${GHIDRA_VERSION} declares minimum JDK: ${GHIDRA_MIN}"; \
               if [ "$JAVA_MAJOR" -lt "$GHIDRA_MIN" ]; then \
                   echo "FATAL: JDK ${JAVA_MAJOR} < Ghidra's declared minimum ${GHIDRA_MIN}" >&2; exit 1; \
               fi; \
           else \
               echo "NOTE: Ghidra application.properties has no application.java.min; relied on REQUIRED_JDK check"; \
           fi \
        && rm -rf /var/lib/apt/lists/* ; \
    else \
        echo "Ghidra not included (build with --build-arg WITH_GHIDRA=1 to enable headless Ghidra)"; \
    fi

# --- Foreign-architecture execution (qemu-user) ---------------------------------
# qemu-<arch> lets the sandbox RUN MIPS/ARM/PPC/… targets (PoC verify + fuzzing) on
# an x86 host. Still --network none, capped, timed; the target is only executed via
# the policy-gated PoC/fuzzing path. The -static variants need no host libs.
# (Placed after Ghidra so a rebuild here keeps the cached Ghidra layer.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-user qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# --- Firmware extraction toolchain ----------------------------------------------
# Real vendor firmware wraps a filesystem (squashfs/jffs2/ubifs/cramfs) in a
# TRX/uImage/vendor header, often with non-standard LZMA. binwalk drives these
# extractors; sasquatch is the patched unsquashfs that handles vendor LZMA squashfs
# that stock unsquashfs chokes on. p7zip/cramfs round out the common formats.
RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full \
        cramfsswap \
        sleuthkit \
        e2tools \
        python3-dev zlib1g-dev liblzma-dev liblzo2-dev liblz4-dev libzstd-dev \
        git build-essential autoconf \
    && pip3 install --no-cache-dir --break-system-packages jefferson ubi_reader \
    # python-lzo (LZO-compressed UBIFS/JFFS2) is a C extension — best-effort.
    && (pip3 install --no-cache-dir --break-system-packages python-lzo \
        || echo "WARN: python-lzo unavailable; LZO-compressed images degraded") \
    # sasquatch (onekey-sec fork): the patched unsquashfs (built from squashfs-tools/
    # with all compressors). Best-effort — the image still works with binwalk +
    # standard unsquashfs if this fails on a given base.
    && (git clone --depth 1 https://github.com/onekey-sec/sasquatch.git /tmp/sasquatch \
        && make -C /tmp/sasquatch/squashfs-tools -j"$(nproc)" \
        && install -m 0755 /tmp/sasquatch/squashfs-tools/sasquatch /usr/local/bin/sasquatch \
        && rm -rf /tmp/sasquatch \
        || echo "WARN: sasquatch build failed; vendor-LZMA squashfs extraction degraded") \
    && rm -rf /var/lib/apt/lists/*

# Bake the probe scripts into the image (no code is mounted at run time, except
# in HEXGRAPH_SANDBOX_DEV mode).
COPY src/hexgraph/sandbox/probes/ /opt/hexgraph/

# Drop privileges: probes never need root.
RUN useradd --create-home --uid 1000 analyst
USER analyst

ENTRYPOINT []
CMD ["python3", "--version"]
