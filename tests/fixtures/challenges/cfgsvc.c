/* cfgsvc — configuration loader for the Halcyon HNVR-8. Reads a binary record
 * from the control socket (stdin here). Fixture — never run outside the sandbox. */
#include <stdio.h>
struct rec { char buf[64]; int tag; };
void unpack_record(struct rec *r, const unsigned char *in);
int main(void) {
    unsigned char in[512];
    size_t n = fread(in, 1, sizeof in, stdin);
    if (n < 2) return 0;
    struct rec r;
    unpack_record(&r, in);
    printf("cfg ok: tag=%d name=%s\n", r.tag, r.buf);
    return 0;
}
