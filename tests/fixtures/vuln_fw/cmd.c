/* cmd.c — command injection (command-injection). Analysis only; never run. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void ping(const char *host) {
    char cmd[512];
    sprintf(cmd, "ping -c1 %s", host);   /* attacker-controlled host */
    system(cmd);                          /* shell injection */
}
int main(int c, char **v) { if (c > 1) ping(v[1]); return 0; }
