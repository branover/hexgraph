/*
 * logsvc.c  ->  /usr/sbin/logsvc   (Phase 5 tooling eval: YARA target, file 1 of 2)
 *
 * A small logging/console service for the fictional "Vantage IoT gateway".  It plants
 * two of the three rule-matching strings the yara_sweep is built to surface:
 *
 *   - the default credential pair  "admin:admin"   -> hexgraph_default_admin_creds
 *   - a known-bad service banner    "Dropbear sshd v2015.67"
 *                                                   -> hexgraph_dropbear_old_banner
 *
 * Both strings are used (printed / compared) so they survive into the binary.
 *
 * Build: cc -fno-stack-protector -no-pie -O0 -o logsvc logsvc.c
 */
#include <stdio.h>
#include <string.h>

/* Default factory login shipped in the image (the credential lead). */
static const char *DEFAULT_LOGIN = "admin:admin";

/* Version/about table — includes the bundled SSH server banner (the n-day lead). */
static const char *ABOUT[] = {
    "Vantage IoT Gateway console logger",
    "build: vantage-logsvc 1.4.0",
    "ssh: Dropbear sshd v2015.67",
    "http: micro-httpd",
};

static void print_about(void)
{
    for (size_t i = 0; i < sizeof(ABOUT) / sizeof(ABOUT[0]); i++)
        puts(ABOUT[i]);
}

/* Trivial "login" check against the baked-in default credential. */
static int check_login(const char *userpass)
{
    if (strcmp(userpass, DEFAULT_LOGIN) == 0) {
        puts("login ok (default credential)");
        return 1;
    }
    puts("login failed");
    return 0;
}

int main(int argc, char **argv)
{
    print_about();
    if (argc > 1)
        return check_login(argv[1]) ? 0 : 1;
    printf("usage: %s user:pass\n", argv[0]);
    printf("hint: factory login is %s\n", DEFAULT_LOGIN);
    return 0;
}
