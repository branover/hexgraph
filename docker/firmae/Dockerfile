# HexGraph FirmAE rehosting image (docs/design/design-rehosting.md).
#
# Wraps FirmAE (full-system firmware emulation) behind the stable rehost_entry.sh contract
# that HexGraph's FirmAERehoster drives. Build:  just firmae-build
#
# This faithfully reproduces FirmAE's own core/Dockerfile toolchain — crucially it builds
# **binwalk 2.3.4 from source** (FirmAE's extractor passes flags like --run-as=root that
# the distro's binwalk 2.2.0 rejects; apt-installing binwalk breaks extraction). Then it
# clones FirmAE, runs its download.sh (prebuilt qemu kernels + sasquatch + binaries), and
# the entry script initializes the firmware DB at runtime. Heavy (multi-GB) and must run
# PRIVILEGED with /dev/net/tun.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV USER=root
# NB: do NOT set FIRMAE_DOCKER — that makes firmae.config point PSQL_IP at the host
# (172.17.0.1). This image runs its OWN postgres, so we want the default PSQL_IP=127.0.0.1.

# FirmAE toolchain deps (from FirmAE core/Dockerfile) — note: NO apt `binwalk` (it'd be
# 2.2.0 and shadow the 2.3.4 we build below, breaking extraction).
RUN apt-get update && apt-get install -y --no-install-recommends \
        apt-utils wget tar bc psmisc ruby telnet ca-certificates git sudo \
        socat net-tools iputils-ping iptables iproute2 curl \
        build-essential python3 python3-dev python3-pip libpq-dev \
        busybox-static bash-static fakeroot kpartx netcat-openbsd nmap \
        snmp uml-utilities util-linux vlan \
        postgresql postgresql-client \
        mtd-utils gzip bzip2 arj lhasa p7zip p7zip-full cabextract cramfsswap \
        squashfs-tools sleuthkit cpio lzop lzma srecord zlib1g-dev liblzma-dev liblzo2-dev liblz4-dev libzstd-dev \
        python3-magic unrar default-jdk \
        qemu-system-arm qemu-system-mips qemu-system-mipsel qemu-system-x86 qemu-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir psycopg2-binary python-lzo cstruct ubi_reader

# binwalk 2.3.4 from source (FirmAE's required version + its extractor flags).
RUN wget -q https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.tar.gz \
    && tar -xf v2.3.4.tar.gz && cd binwalk-2.3.4 \
    && sed -i 's/^install_ubireader//g' deps.sh \
    && sed -i 's/^REQUIRED_UTILS="wget tar python"/REQUIRED_UTILS="wget tar python3"/g' deps.sh \
    && (echo y | ./deps.sh || true) \
    && python3 setup.py install \
    && cd / && rm -rf v2.3.4.tar.gz binwalk-2.3.4

# sasquatch (onekey-sec fork) — the patched unsquashfs FirmAE's extractor invokes by name to
# unpack vendor/LZMA squashfs (most real vendor firmware; stock unsquashfs chokes on it).
# FirmAE's download.sh doesn't reliably put it on PATH, so build + install it ourselves.
RUN (git clone --depth 1 https://github.com/onekey-sec/sasquatch.git /tmp/sasquatch \
        && make -C /tmp/sasquatch/squashfs-tools -j"$(nproc)" \
        && install -m 0755 /tmp/sasquatch/squashfs-tools/sasquatch /usr/local/bin/sasquatch \
        && rm -rf /tmp/sasquatch) \
    || echo "WARN: sasquatch build failed; vendor-LZMA squashfs extraction degraded"

# Clone FirmAE and fetch its prebuilt binaries (qemu kernels, console, etc.).
ARG FIRMAE_REF=master
RUN git clone --depth 1 --branch "${FIRMAE_REF}" https://github.com/pr0v3rbs/FirmAE /FirmAE
WORKDIR /FirmAE
# FirmAE ships a passthrough `sudo` + `unstuff` (under core/) — install them so its scripts,
# which call sudo liberally, work in-container.
RUN cp core/sudo /usr/bin/sudo && chmod 755 /usr/bin/sudo && cp core/unstuff /usr/local/bin/ || true
RUN ./download.sh

# Set up the firmadyne/firmware postgres DB at build time (FirmAE's install.sh DB steps).
RUN service postgresql start \
    && su postgres -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" \
    && su postgres -c "createdb -O firmadyne firmware" \
    && su postgres -c "psql -d firmware < /FirmAE/database/schema" \
    && service postgresql stop

COPY docker/firmae/rehost_entry.sh /rehost_entry.sh
RUN chmod +x /rehost_entry.sh
ENTRYPOINT ["/rehost_entry.sh"]
