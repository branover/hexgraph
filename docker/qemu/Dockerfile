# HexGraph qemu disk-image rehosting image (docs/design-rehosting.md).
#
# Boots a FULL-OS disk image (a bootable VM disk: .vmdk/.qcow2/.vdi or a partitioned x86
# .img — e.g. IoTGoat x86 / OpenWrt) under qemu-system-x86_64 + KVM, as-is (the image's own
# kernel + init), behind the stable rehost_entry contract HexGraph's QemuDiskRehoster drives.
# Build:  make qemu-build  ·  run needs --device /dev/kvm (no privilege required).
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-x86 qemu-utils curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY docker/qemu/qemu_entry.sh /qemu_entry.sh
RUN chmod +x /qemu_entry.sh
ENTRYPOINT ["/qemu_entry.sh"]
