/* record.c — TLV record unpacker, copied VERBATIM into several Halcyon services.
 * The classic embedded "trust the length byte" bug. */
#include <string.h>
struct rec { char buf[64]; int tag; };

void unpack_record(struct rec *out, const unsigned char *in) {
    char local[64];
    unsigned int len = in[0];          /* attacker-controlled length byte */
    memcpy(local, in + 2, len);        /* BUG: len 0..255 copied into a 64-byte stack buffer */
    local[len] = '\0';
    out->tag = in[1];
    memcpy(out->buf, local, sizeof out->buf);
}
