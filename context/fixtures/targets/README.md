# Test targets

Generate these and commit them under the repo's `tests/fixtures/` so `make demo` and the acceptance run work offline. They are intentionally tiny and intentionally vulnerable. Keep them in the repo (they are not secret) so CI is hermetic.

## 1. `vuln_httpd` — a single vulnerable ELF
A minimal C program that mimics a CGI request handler with an obvious, fuzzer-and-static-analysis-findable bug. Compile **without** stack protector / PIE so recon reports weak mitigations (matches the mock fixtures).

```c
/* vuln_httpd.c — DO NOT run as a network service; for analysis only. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void cgi_handler(const char *token) {
    char buf[1040];
    strcpy(buf, token);          /* unbounded copy: stack overflow */
    printf("handled %s\n", buf);
}

int parse_request(char *body) {  /* a 'parser' entry point for harness_generation */
    char *t = strtok(body, "&");
    while (t) { if (!strncmp(t, "token=", 6)) cgi_handler(t + 6); t = strtok(NULL, "&"); }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) parse_request(argv[1]);
    return 0;
}
```

Build (Linux):
```
cc -fno-stack-protector -no-pie -z norelro -O0 -o vuln_httpd vuln_httpd.c
```
Expected recon: ELF, x86-64 (or your host arch), imports `strcpy`/`strtok`/`printf`, mitigations NX=on, canary=off, PIE=off. `static_analysis` on `cgi_handler` should surface the overflow (mock: `critical_overflow`).

## 2. `synthetic_fw.bin` — a small fake firmware image
A container that `binwalk` can unpack into 2–3 small ELFs so ingestion creates child targets + `contains` edges and `pattern_sweep` has siblings to match against.

Quick recipe (cpio or squashfs both fine):
```
mkdir -p fwroot/sbin fwroot/usr/lib
cp vuln_httpd fwroot/sbin/httpd
cc -fno-stack-protector -no-pie -O0 -o fwroot/usr/lib/libupnp.so -shared -fPIC libupnp.c   # a 2nd ELF with a similar strcpy sink
printf 'placeholder' > fwroot/usr/lib/libcrypto.so.dummy
# squashfs:
mksquashfs fwroot synthetic_fw.bin -noappend
# (or cpio:)  (cd fwroot && find . | cpio -o -H newc) > synthetic_fw.bin
```
Where `libupnp.c` contains an `ssdp_recv()` with the same unbounded `strcpy` shape so the `pattern_sweep` mock (`match_found`) corresponds to something real after templating.

Expected ingest: root `firmware_image` target with `contains` edges to `httpd` and `libupnp.so`; recon on each; a `pattern_sweep` from the httpd overflow finding creates a `related_to` edge to `libupnp.so` and a new finding on it.

> If `mksquashfs`/`binwalk` aren't available in CI, a plain cpio/tar that your unpacker recognizes is acceptable for the MVP — the point is that one input expands into multiple child targets.
