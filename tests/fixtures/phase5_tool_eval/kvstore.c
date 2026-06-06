/*
 * kvstore.c  ->  /usr/bin/kvstore   (Phase 5 tooling eval: YARA target, file 2 of 2)
 *
 * A tiny key/value config store for the fictional "Vantage IoT gateway".  It plants
 * the third (and weak-crypto) set of rule-matching strings the yara_sweep surfaces:
 *
 *   - "DES-CBC"   (deprecated cipher named in the config crypto profile)
 *                                            -> hexgraph_des_constants
 *   - "MD5_Init"  (weak hash used for the config MAC)
 *                                            -> hexgraph_weak_hash_md5_sha1_banner
 *
 * Both strings are printed so they survive into the binary; spreading the weak-crypto
 * lead onto a SECOND executable is what makes a corpus-wide yara_sweep (not a single
 * file scan) the tool that reveals the full picture.
 *
 * Build: cc -fno-stack-protector -no-pie -O0 -o kvstore kvstore.c
 */
#include <stdio.h>
#include <string.h>

/* Crypto profile baked into the config store (the weak-crypto leads). */
static const char *CIPHER = "DES-CBC";
static const char *CONFIG_MAC = "MD5_Init";

static void print_crypto_profile(void)
{
    printf("config crypto profile:\n");
    printf("  cipher = %s\n", CIPHER);   /* DES-CBC */
    printf("  mac    = %s\n", CONFIG_MAC); /* MD5_Init */
}

/* A toy MAC stand-in: folds the bytes so CONFIG_MAC ("MD5_Init") is referenced
 * on a live path and survives optimization. */
static unsigned int config_mac(const char *data)
{
    unsigned int acc = 0;
    for (const char *p = CONFIG_MAC; *p; p++)
        acc = acc * 31u + (unsigned char)*p;
    for (const char *p = data; *p; p++)
        acc = acc * 31u + (unsigned char)*p;
    return acc;
}

int main(int argc, char **argv)
{
    print_crypto_profile();
    const char *blob = (argc > 1) ? argv[1] : "factory-defaults";
    printf("mac(%s) [%s] = 0x%08x\n", blob, CONFIG_MAC, config_mac(blob));
    printf("sealed with %s\n", CIPHER);
    return 0;
}
