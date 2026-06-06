/* Fixture for the FLOSS string-deobfuscation probe (Phase 5A PR 5A-2).
 *
 * Built as a Windows PE32+ (x86-64) because FLOSS's stack/tight/decoded-string
 * EMULATION (vivisect) supports the PE format only; on ELF it recovers static
 * strings alone. The probe degrades gracefully on ELF/foreign-arch, but to prove
 * it recovers a HIDDEN string we need a PE.
 *
 * It hides two strings a plain `strings` pass misses:
 *   - a STACK STRING built one byte at a time on the stack at runtime, and
 *   - a string XOR-DECODED by a small routine FLOSS lightly emulates.
 * Neither appears as a contiguous literal in the binary's data.
 */
#include <stdio.h>

/* A decode routine FLOSS emulates to recover the plaintext. */
__attribute__((noinline))
static void decode(char *out, const unsigned char *in, int n, unsigned char key) {
    int i;
    for (i = 0; i < n; i++) out[i] = (char)(in[i] ^ key);
    out[n] = 0;
}

int main(int argc, char **argv) {
    /* STACK STRING: "STACKSTRING" assembled byte-by-byte on the stack. */
    volatile char stk[16];
    stk[0]='S'; stk[1]='T'; stk[2]='A'; stk[3]='C'; stk[4]='K';
    stk[5]='S'; stk[6]='T'; stk[7]='R'; stk[8]='I'; stk[9]='N';
    stk[10]='G'; stk[11]=0;

    /* DECODED STRING: "DECODEDSECRET" XORed with 0x5A in .data, decoded at runtime. */
    static const unsigned char enc[] = {
        'D'^0x5A,'E'^0x5A,'C'^0x5A,'O'^0x5A,'D'^0x5A,'E'^0x5A,'D'^0x5A,
        'S'^0x5A,'E'^0x5A,'C'^0x5A,'R'^0x5A,'E'^0x5A,'T'^0x5A
    };
    char dec[16];
    decode(dec, enc, 13, 0x5A);

    printf("%s %s %d\n", (const char *)stk, dec, argc);
    return 0;
}
