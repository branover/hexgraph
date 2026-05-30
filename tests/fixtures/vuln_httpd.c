/* vuln_httpd.c — DO NOT run as a network service; for analysis only.
 * A minimal fake CGI request handler with an obvious unbounded strcpy. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void cgi_handler(const char *token) {
    char buf[1040];
    strcpy(buf, token);          /* unbounded copy: stack overflow */
    printf("handled %s\n", buf);
}

int parse_request(char *body) {  /* a 'parser' entry point for harness_generation */
    char *t = strtok(body, "&");
    while (t) { if (!strncmp(t, "token=", 6)) cgi_handler(t + 6); t = strtok(NULL, "&"); }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) parse_request(argv[1]);
    return 0;
}
