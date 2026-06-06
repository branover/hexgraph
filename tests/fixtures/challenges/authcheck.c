/*
 * authcheck — minimal credential check for the function-facts fixture. Compiled WITHOUT
 * debug info (-O0, no -g): Ghidra knows the exported name but NOT the signature, so the
 * pre-decompile listing DB shows `undefined check_password(void)` with `undefinedN` locals.
 * The DECOMPILER recovers the real shape — a char* parameter and typed locals — which is
 * what the focus facts should store. Analysis fixture — never run.
 */
#include <string.h>

int check_password(const char *pw) {
    char buf[64];
    int i;
    strncpy(buf, pw, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    for (i = 0; buf[i]; i++)
        buf[i] ^= 0x2a;
    return strcmp(buf, "Zm9vYmFy") == 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 1;
    return check_password(argv[1]) ? 0 : 2;
}
