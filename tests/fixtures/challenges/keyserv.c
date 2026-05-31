/*
 * keyserv — a tiny license/registration daemon helper.
 * Validates a license key taken from the environment (set by the CGI front-end
 * from an HTTP header). Analysis fixture for HexGraph — never run it directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Returns 1 if the key's checksum matches the embedded magic, else 0. */
static int verify_key(const char *key) {
    unsigned int sum = 0;
    for (const char *p = key; *p; p++) sum += (unsigned char)*p;
    return sum == 0x4242;  /* "magic" checksum */
}

/* BUG: bounds check uses 256 but the buffer is 64 bytes. A key between 65 and
 * 255 bytes overflows `local` on the stack. No canary / PIE on this build, so
 * the saved return address is overwritable. `key` is attacker-controlled (the
 * LICENSE env var, populated pre-auth from a request header). */
void register_license(const char *key) {
    char local[64];
    if (strlen(key) > 256) {            /* wrong limit — should be sizeof(local) */
        fprintf(stderr, "key too long\n");
        return;
    }
    strcpy(local, key);                  /* stack buffer overflow */
    if (verify_key(local))
        printf("license OK: %s\n", local);
    else
        printf("license rejected\n");
}

int main(void) {
    const char *key = getenv("LICENSE");
    if (key) register_license(key);
    return 0;
}
