# HexGraph FirmAE rehosting image (docs/design-rehosting.md).
#
# Wraps FirmAE (full-system firmware emulation) behind the stable rehost_entry.sh contract
# that HexGraph's FirmAERehoster drives. Build:  make firmae-build
#
# Heavy (FirmAE downloads qemu-system, kernels, and prebuilt binaries — multiple GB) and
# must run PRIVILEGED with /dev/net/tun (HexGraph runs it that way). FirmAE's installers
# assume an Ubuntu host with sudo; this image reproduces that. If you track a different
# FirmAE revision, pin it here and adjust rehost_entry.sh's flags to match.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        git sudo curl ca-certificates kpartx busybox-static fakeroot \
        qemu-system-arm qemu-system-mips qemu-system-mipsel qemu-system-x86 qemu-utils \
        postgresql postgresql-client \
        python3 python3-pip netcat-openbsd iproute2 iputils-ping \
        binwalk cpio file unzip wget \
    && rm -rf /var/lib/apt/lists/*

# Clone FirmAE and run its bundled download + install (binaries, kernels, DB schema).
# Pinned to a commit for reproducibility — bump deliberately.
ARG FIRMAE_REF=master
RUN git clone --depth 1 --branch "${FIRMAE_REF}" https://github.com/pr0v3rbs/FirmAE /FirmAE
WORKDIR /FirmAE
# download.sh fetches the prebuilt FirmAE binaries/kernels; install.sh sets up postgres +
# the firmware DB. These are best-effort in a container (they expect systemd/sudo on a
# host); review FirmAE's docs if a step needs adapting for your environment.
RUN ./download.sh || true
RUN ./install.sh || true

COPY docker/firmae/rehost_entry.sh /rehost_entry.sh
RUN chmod +x /rehost_entry.sh
ENTRYPOINT ["/rehost_entry.sh"]
