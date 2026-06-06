/*
 * licensegate.c  ->  licensegate   (Phase 5 tooling eval: forces angr / symbolic exec)
 *
 * Gates a privileged action (system("/bin/grant_admin")) behind an 8-byte serial
 * check.  The only valid serial is defined IMPLICITLY by arithmetic constraints, not
 * stored anywhere in plain form, so strings/FLOSS reveal nothing — only symbolic
 * execution solves for a satisfying input.
 *
 * check_serial(s) over the 8 input bytes requires ALL of:
 *     s[0]*7 + s[1]        == 0x1c2   (450)
 *     s[2] ^ s[3]          == 0x5a
 *     (s[4] | 0x20)        == 'k'
 *     rolling_sum(s, 8)    == 0x4d2   (1234)        where rolling_sum is the
 *                                                   weighted sum  sum s[i]*(i+1)
 *
 * The constraints are satisfiable (a witness exists); no valid serial appears as a
 * literal in the binary.
 *
 * Build: cc -fno-stack-protector -no-pie -O0 -o licensegate licensegate.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Order-dependent rolling checksum: each byte weighted by its 1-based position. */
static unsigned int rolling_sum(const unsigned char *s, int n)
{
    unsigned int acc = 0;
    for (int i = 0; i < n; i++)
        acc += (unsigned int)s[i] * (unsigned int)(i + 1);
    return acc;
}

/* Returns 1 iff the 8-byte serial satisfies every gate constraint. */
static int check_serial(const unsigned char *s)
{
    if ((unsigned int)s[0] * 7u + (unsigned int)s[1] != 0x1c2u)
        return 0;
    if ((s[2] ^ s[3]) != 0x5a)
        return 0;
    if ((s[4] | 0x20) != 'k')
        return 0;
    if (rolling_sum(s, 8) != 0x4d2u)
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        puts("usage: licensegate <serial>");
        return 2;
    }
    if (strlen(argv[1]) < 8) {
        puts("Access denied");
        return 1;
    }
    if (check_serial((const unsigned char *)argv[1])) {
        puts("License valid.");
        return system("/bin/grant_admin");   /* privileged action (the sink) */
    }
    puts("Access denied");
    return 1;
}
