/* libupnp.c — fake UPnP/SSDP parser with the SAME unbounded strcpy shape as
 * vuln_httpd's cgi_handler, so pattern_sweep has a real sibling to match.
 * Analysis only; never executed. */
#include <string.h>
#include <stdio.h>

struct pkt { char *location; };

void ssdp_recv(struct pkt *p) {
    char buf[512];
    strcpy(buf, p->location);    /* unbounded copy: same sink as cgi_handler */
    printf("ssdp %s\n", buf);
}
