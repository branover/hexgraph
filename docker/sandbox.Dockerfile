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
# only when enabled in Settings. analyzeHeadless lands at $GHIDRA_INSTALL_DIR.
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
# Temurin lands at a versioned path; point JAVA_HOME/PATH at it so analyzeHeadless
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
        # Install the bundled Jython extension so classic `.py` postScripts run under
        # analyzeHeadless. Ghidra 11.x+ no longer bundles Jython enabled by default and
        # routes `.py` scripts through PyGhidra (which needs a separate launcher); our
        # ghidra_probe.py uses the classic `-postScript hexgraph_post.py` path, so without
        # this the run aborts with "Ghidra was not started with PyGhidra. Python is not
        # available" and produces no output. The Jython extension restores `.py` support
        # in-place; ship it so headless decompilation actually works.
        && JYTHON_ZIP="$(ls /opt/ghidra/Extensions/Ghidra/*Jython*.zip | head -n1)" \
        && if [ -z "$JYTHON_ZIP" ]; then echo "FATAL: bundled Jython extension not found" >&2; exit 1; fi \
        && mkdir -p /opt/ghidra/Ghidra/Extensions \
        && unzip -q "$JYTHON_ZIP" -d /opt/ghidra/Ghidra/Extensions \
        # PyGhidra's script provider claims `.py` ahead of Jython, but it can only run
        # when Ghidra is launched through the separate `pyghidra` launcher (a pip install
        # + jpype bridge) — under plain `analyzeHeadless` it aborts every `.py` postScript
        # with "Ghidra was not started with PyGhidra. Python is not available". We launch
        # headless the classic way and want Jython to own `.py`, so drop the PyGhidra
        # feature. (radare2 remains the default decompiler; Ghidra is the opt-in upgrade.)
        && rm -rf /opt/ghidra/Ghidra/Features/PyGhidra \
        # Ghidra Bridge (features.ghidra bridge / re_bridge_*): a long-lived analyzeHeadless can
        # host a ghidra_bridge RPC server, keeping an analyzed project RESIDENT so repeated
        # decompile/xref/taint/emulate calls for a target skip the per-call project open. The
        # server runs in Ghidra's Jython (2.7); bake its server scripts + jfx_bridge into a fixed
        # dir that the harness (sandbox/probes/ghidra_bridge_serve.py, a mounted probe) adds to
        # sys.path. Pure-Python, Jython-importable; --break-system-packages for PEP 668.
        && python3 -m pip install --no-cache-dir --break-system-packages ghidra_bridge \
        && mkdir -p /opt/ghidra-bridge \
        && cp "$(python3 -c 'import ghidra_bridge, os; print(os.path.dirname(ghidra_bridge.__file__))')"/server/*.py /opt/ghidra-bridge/ \
        && cp -r "$(python3 -c 'import jfx_bridge, os; print(os.path.dirname(jfx_bridge.__file__))')" /opt/ghidra-bridge/jfx_bridge \
        && chmod -R a+rX /opt/ghidra-bridge \
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
