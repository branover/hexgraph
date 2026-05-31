/*
 * netcfgd — LAN configuration service helper for the "Orbweaver" gateway.
 * Handles a small XML control request on stdin (posted by the web UI's
 * /ctl endpoint) and applies a network diagnostic. Analysis fixture — never run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull the text between <tag>...</tag> out of the request body. */
static int extract(const char *body, const char *tag, char *out, size_t n) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *a = strstr(body, open);
    if (!a) return 0;
    a += strlen(open);
    const char *b = strstr(a, close);
    size_t len = b ? (size_t)(b - a) : strlen(a);
    if (len >= n) len = n - 1;
    memcpy(out, a, len);
    out[len] = '\0';
    return 1;
}

/* "Sanitize" a value before it goes near the shell. NOTE: this blocks the
 * obvious metacharacters but is incomplete — it does not handle backticks,
 * $(...) command substitution, or newlines. (Mirrors a real-world partial fix.) */
static void sanitize(char *s) {
    for (char *p = s; *p; p++)
        if (*p == ';' || *p == '|' || *p == '&' || *p == '>' || *p == '<')
            *p = '_';
}

/* Applies the requested diagnostic to the given host. The host value is taken
 * from the request, passed through sanitize(), then interpolated into a shell
 * command run via popen. */
static void run_probe(const char *host, const char *mode) {
    char hbuf[128], cmd[256];
    char out[512];
    strncpy(hbuf, host, sizeof(hbuf) - 1);
    hbuf[sizeof(hbuf) - 1] = '\0';
    sanitize(hbuf);                        /* incomplete — backtick/$()/newline pass */
    if (strcmp(mode, "lookup") == 0)
        snprintf(cmd, sizeof(cmd), "nslookup %s 2>&1", hbuf);
    else
        snprintf(cmd, sizeof(cmd), "ping -c 2 %s 2>&1", hbuf);
    FILE *fp = popen(cmd, "r");            /* command injection via unsanitized metachars */
    if (!fp) return;
    while (fgets(out, sizeof(out), fp)) fputs(out, stdout);
    pclose(fp);
}

int main(void) {
    char body[2048];
    size_t n = fread(body, 1, sizeof(body) - 1, stdin);
    body[n] = '\0';
    char host[256] = "127.0.0.1", mode[32] = "ping";
    extract(body, "Host", host, sizeof(host));
    extract(body, "Mode", mode, sizeof(mode));
    run_probe(host, mode);
    return 0;
}
