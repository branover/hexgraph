/*
 * stringcrypt.c  ->  stringcrypt.exe   (Phase 5 tooling eval: forces floss_strings)
 *
 * A small Windows (PE32+) "relay agent" that hides its real indicators of compromise
 * so a plain `strings` / list_strings pass shows only innocuous decoys.  Two secrets:
 *
 *   - The API key  MITISKEY-7F3A9C  is stored XOR-obfuscated (key 0x5a) in g_enc[]
 *     and recovered at runtime by decode().  FLOSS's decoded-string recovery sees it.
 *
 *   - The C2 URL  http://relay.mitis-labs.net/ingest  is never a contiguous literal:
 *     build_cfg() writes it onto the stack one byte at a time through a `volatile`
 *     index so the compiler cannot fold it into a rodata string.  FLOSS's stack-string
 *     emulation reconstructs it.
 *
 * The decoys "Mitis Relay Agent" and "OK" ARE plain literals, so a surface strings
 * dump looks productive while revealing nothing real.
 *
 * MUST be a PE32+: FLOSS's stack/decoded-string emulation (vivisect) supports PE only;
 * on ELF it degrades to a plain static-strings pass and would not force the tool.
 *
 * Build (mingw):  x86_64-w64-mingw32-gcc -O0 -o stringcrypt.exe stringcrypt.c
 */
#include <stdio.h>
#include <stddef.h>

/* "MITISKEY-7F3A9C" each byte XORed with 0x5a.  No plaintext fragment appears. */
static const unsigned char g_enc[] = {
    0x17, 0x13, 0x0e, 0x13, 0x09, 0x11, 0x1f, 0x03,
    0x77, 0x6d, 0x1c, 0x69, 0x1b, 0x63, 0x19,
};

/* Runtime XOR decode of the API key. */
static void decode(const unsigned char *enc, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(enc[i] ^ 0x5a);
    out[n] = '\0';
}

/* Build the C2 URL on the stack, one byte at a time.  The volatile index defeats
 * any constant folding that would otherwise materialize a contiguous literal. */
static void build_cfg(char *out)
{
    volatile int i = 0;
    out[i++] = 'h'; out[i++] = 't'; out[i++] = 't'; out[i++] = 'p';
    out[i++] = ':'; out[i++] = '/'; out[i++] = '/'; out[i++] = 'r';
    out[i++] = 'e'; out[i++] = 'l'; out[i++] = 'a'; out[i++] = 'y';
    out[i++] = '.'; out[i++] = 'm'; out[i++] = 'i'; out[i++] = 't';
    out[i++] = 'i'; out[i++] = 's'; out[i++] = '-'; out[i++] = 'l';
    out[i++] = 'a'; out[i++] = 'b'; out[i++] = 's'; out[i++] = '.';
    out[i++] = 'n'; out[i++] = 'e'; out[i++] = 't'; out[i++] = '/';
    out[i++] = 'i'; out[i++] = 'n'; out[i++] = 'g'; out[i++] = 'e';
    out[i++] = 's'; out[i++] = 't'; out[i++] = '\0';
}

/* volatile sink so the decode/build routines (and their outputs) are not stripped */
volatile unsigned char g_keep;

int main(void)
{
    /* decoys — plain literals, so a strings dump looks productive */
    puts("Mitis Relay Agent");

    char key[32];
    decode(g_enc, sizeof g_enc, key);

    char url[64];
    build_cfg(url);

    /* consume both secrets so the compiler keeps the obfuscation code */
    for (int i = 0; key[i]; i++)
        g_keep ^= (unsigned char)key[i];
    for (int i = 0; url[i]; i++)
        g_keep ^= (unsigned char)url[i];

    /* a benign-looking heartbeat */
    puts("OK");
    return (int)(g_keep & 0);
}
