/*
 * diagnostic.cgi — network-diagnostics CGI for the "Aria" home router.
 *
 * Serves /cgi-bin/diagnostic on the LAN admin web UI. Lets the admin ping or
 * traceroute a host from the device. Reachable pre-auth on this firmware (the
 * admin UI gates on a cookie the diagnostics handler never checks).
 *
 * Build/analysis fixture for HexGraph. NEVER run it — it is intentionally
 * vulnerable. It is analyzed statically inside the sandbox.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER "Aria Router AC1200 — diagnostics 1.2.3"

/* Minimal in-place URL-decode (%xx and '+'). */
static void url_decode(char *s) {
    char *o = s;
    for (char *p = s; *p; p++) {
        if (*p == '%' && p[1] && p[2]) {
            int hi = p[1], lo = p[2];
            hi = (hi >= 'a') ? hi - 'a' + 10 : (hi >= 'A') ? hi - 'A' + 10 : hi - '0';
            lo = (lo >= 'a') ? lo - 'a' + 10 : (lo >= 'A') ? lo - 'A' + 10 : lo - '0';
            *o++ = (char)((hi << 4) | lo);
            p += 2;
        } else if (*p == '+') {
            *o++ = ' ';
        } else {
            *o++ = *p;
        }
    }
    *o = '\0';
}

/* Pull one field out of an application/x-www-form-urlencoded query string. */
static int get_param(const char *qs, const char *key, char *out, size_t n) {
    size_t klen = strlen(key);
    const char *p = qs;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *amp = strchr(v, '&');
            size_t len = amp ? (size_t)(amp - v) : strlen(v);
            if (len >= n) len = n - 1;
            memcpy(out, v, len);
            out[len] = '\0';
            url_decode(out);
            return 1;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return 0;
}

/*
 * Runs the requested diagnostic. `host` comes straight from the HTTP query
 * string. It is interpolated into a shell command with no validation, so a
 * value like "8.8.8.8; telnetd -l/bin/sh -p9999" yields remote command
 * execution as the web server's user (root on this firmware).
 */
void run_diagnostic(const char *mode, const char *host) {
    char cmd[256];
    if (strcmp(mode, "traceroute") == 0)
        snprintf(cmd, sizeof(cmd), "traceroute -n %s 2>&1", host);
    else
        snprintf(cmd, sizeof(cmd), "ping -c 4 %s 2>&1", host);  /* host is attacker-controlled */
    printf("Content-Type: text/plain\r\n\r\n");
    fflush(stdout);
    system(cmd);   /* command injection -> RCE */
}

int main(void) {
    char host[128] = "127.0.0.1";
    char mode[32] = "ping";
    const char *qs = getenv("QUERY_STRING");
    if (qs) {
        get_param(qs, "host", host, sizeof(host));
        get_param(qs, "mode", mode, sizeof(mode));
    }
    run_diagnostic(mode, host);
    return 0;
}
