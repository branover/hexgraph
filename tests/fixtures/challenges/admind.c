/*
 * admind — admin control daemon for the Sentry SX-3 access controller.
 * Verifies an admin token before unlocking a privileged action. Reads a
 * "TOKEN=<value>" request line from the control socket (stdin). Fixture.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compare the supplied token against the secret. BUG: the comparison length is
 * the length of the ATTACKER's token, so a short/empty token only has to match a
 * prefix of the secret (an empty token matches everything) — auth bypass. */
static int check_token(const char *got, const char *secret) {
    return strncmp(got, secret, strlen(got)) == 0;   /* length from attacker input */
}

static const char *field(char *line, const char *key) {
    size_t kn = strlen(key);
    if (strncmp(line, key, kn) == 0 && line[kn] == '=')
        return line + kn + 1;
    return NULL;
}

int main(void) {
    const char *secret = getenv("ADMIN_TOKEN");      /* the real admin token */
    const char *flag = getenv("PRIV_FLAG");          /* shown only once unlocked */
    if (!secret) secret = "sx3-default-do-not-ship";
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\r\n")] = '\0';
    const char *tok = field(line, "TOKEN");
    if (tok && check_token(tok, secret))
        printf("ACCESS GRANTED %s\n", flag ? flag : "(no flag set)");
    else
        printf("access denied\n");
    return 0;
}
