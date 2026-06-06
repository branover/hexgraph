/*
 * keytab — a named global data symbol referenced from code, for the data-xrefs-by-name
 * fixture. KEY_ENC has external linkage so it lands in the symbol table by name (not stripped),
 * letting `data_xrefs("KEY_ENC")` resolve the name to its address via the symbol table.
 * Analysis fixture — never run.
 */
#include <string.h>

const unsigned char KEY_ENC[16] = {
    0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
};

int verify(const unsigned char *in) {
    return memcmp(in, KEY_ENC, sizeof(KEY_ENC)) == 0;   /* references KEY_ENC */
}

int main(int argc, char **argv) {
    return (argc > 1) ? verify((const unsigned char *)argv[1]) : 1;
}
