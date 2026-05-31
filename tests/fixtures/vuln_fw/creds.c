/* creds.c — hardcoded credential (hardcoded-secret). Analysis only; never run. */
#include <string.h>
#include <stdio.h>
static const char *ADMIN_PASSWORD = "S3cr3t-Backdoor-2024";  /* hardcoded secret */
int login(const char *user, const char *pass) {
    if (strcmp(user, "admin") == 0 && strcmp(pass, ADMIN_PASSWORD) == 0) return 1;
    return 0;
}
int main(int c, char **v) { if (c > 2) printf("%d\n", login(v[1], v[2])); return 0; }
