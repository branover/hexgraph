#!/usr/bin/env bash
# Build the multi-vuln test set (P8): tiny ELFs each planting one distinct,
# statically-findable bug. Committed so the scored real-key test (make test-live)
# and the no-key recon checks are hermetic. Weak mitigations to match recon.
set -euo pipefail
cd "$(dirname "$0")"
CFLAGS="-fno-stack-protector -no-pie -z norelro -O0 -w"
for src in cgi cmd creds; do
    cc $CFLAGS -o "$src" "$src.c"
done
echo "built: cgi cmd creds"
