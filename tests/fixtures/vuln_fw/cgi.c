/* cgi.c — stack buffer overflow (memory-safety). Analysis only; never run. */
#include <string.h>
#include <stdio.h>
void handle(const char *req) {
    char buf[256];
    strcpy(buf, req);            /* unbounded copy from request */
    printf("ok %s\n", buf);
}
int main(int c, char **v) { if (c > 1) handle(v[1]); return 0; }
