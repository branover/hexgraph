/*
 * pingd — connectivity-diagnostic helper for the "Orbweaver" gateway. Reads a
 * single request line from stdin and runs a probe against the host it names.
 * Analysis fixture — never run.
 *
 * Unlike netcfgd (where the tainted value crosses a function parameter), here the
 * untrusted input enters via fgets() into a LOCAL buffer and reaches system()
 * WITHIN main — the self-contained / inlined-handler shape common to firmware and
 * CTF binaries. The parameter-only taint source set misses this; the libc-input
 * source set (fgets, and the strtok hop that returns a pointer into the tainted
 * buffer) is what catches it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    char cmd[300];

    if (!fgets(line, sizeof(line), stdin))      /* untrusted input -> local buffer */
        return 1;
    line[strcspn(line, "\n")] = '\0';

    /* First whitespace-separated token is the host. strtok returns a pointer INTO
       the (tainted) line buffer, so the taint must ride through it. */
    char *host = strtok(line, " \t");
    if (!host)
        return 1;

    sprintf(cmd, "ping -c 1 %s 2>&1", host);    /* taints cmd from host */
    system(cmd);                                /* command injection */
    return 0;
}
