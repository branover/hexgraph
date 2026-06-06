/*
 * mitis_relayd.c  ->  mitis_relayd   (Phase 5 tooling eval: forces binutils_facts)
 *
 * A believable field-bus relay daemon for the fictional "Mitis EdgeRelay" appliance.
 * Two planted properties make this target solvable ONLY with binutils_facts, not a
 * plain recon/strings pass:
 *
 *   1) It is built with `-z execstack` so the GNU_STACK segment is executable
 *      (NX off). recon does not report exec-stack; binutils_facts reports nx=false.
 *
 *   2) On a reachable request-opcode path it assembles a command from request bytes
 *      and calls system().  But the binary references ~90 distinct libc functions, so
 *      the `system` import is buried far past recon's 60-import display cap.  Only the
 *      full dynamic-symbol / jump-slot map from binutils_facts surfaces `system`.
 *
 * The wide libc reference set below is deliberate import-cap padding: every symbol is
 * address-taken into a table that a volatile accumulator consumes, so the linker keeps
 * each as an undefined dynamic symbol (an entry recon would have to cap).
 *
 * Build: cc -fno-stack-protector -no-pie -z execstack -O0 -o mitis_relayd mitis_relayd.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>

/* ---- config / session state for a plausible relay daemon ---------------- */

struct relay_cfg {
    char  endpoint[128];
    int   port;
    int   verbose;
    long  seq;
};

static struct relay_cfg g_cfg;
static volatile unsigned long g_sink;   /* keeps the symbol table live */

/* Reference a broad spread of libc (and libm) so the dynamic symbol table is
 * large enough to bury `system` past recon's import cap.  Address-taking forces
 * a jump-slot/relocation per symbol; the volatile accumulator defeats DCE. */
static void load_relay_extensions(void)
{
    void *tab[] = {
        /* string.h */
        (void*)strlen,  (void*)strcpy,  (void*)strncpy, (void*)strcat,
        (void*)strncat, (void*)strcmp,  (void*)strncmp, (void*)strchr,
        (void*)strrchr, (void*)strstr,  (void*)strtok,  (void*)strdup,
        (void*)strndup, (void*)memcpy,  (void*)memmove, (void*)memset,
        (void*)memcmp,  (void*)memchr,  (void*)strpbrk, (void*)strspn,
        (void*)strcspn, (void*)strsep,  (void*)strerror,
        /* strings.h */
        (void*)strcasecmp, (void*)strncasecmp,
        /* stdio.h */
        (void*)printf,  (void*)fprintf, (void*)sprintf, (void*)snprintf,
        (void*)sscanf,  (void*)fopen,   (void*)fclose,  (void*)fread,
        (void*)fwrite,  (void*)fgets,   (void*)fputs,   (void*)fputc,
        (void*)fgetc,   (void*)puts,    (void*)putchar, (void*)perror,
        (void*)fflush,  (void*)fseek,   (void*)ftell,   (void*)rewind,
        (void*)setvbuf, (void*)rename,  (void*)remove,
        /* stdlib.h */
        (void*)malloc,  (void*)calloc,  (void*)realloc, (void*)free,
        (void*)atoi,    (void*)atol,    (void*)strtol,  (void*)strtoul,
        (void*)strtod,  (void*)qsort,   (void*)bsearch, (void*)abs,
        (void*)labs,    (void*)rand,    (void*)srand,   (void*)getenv,
        (void*)setenv,  (void*)system,  (void*)atexit,  (void*)mkstemp,
        /* time.h */
        (void*)time,    (void*)localtime, (void*)gmtime, (void*)mktime,
        (void*)strftime,(void*)difftime,  (void*)clock,  (void*)ctime,
        (void*)asctime,
        /* ctype.h */
        (void*)isalpha, (void*)isdigit, (void*)isalnum, (void*)isspace,
        (void*)isupper, (void*)islower, (void*)toupper, (void*)tolower,
        (void*)isxdigit,(void*)ispunct,
        /* unistd.h */
        (void*)getpid,  (void*)getppid, (void*)sleep,   (void*)usleep,
        (void*)access,  (void*)read,    (void*)write,   (void*)close,
        (void*)unlink,  (void*)getcwd,  (void*)chdir,   (void*)dup,
        /* math.h (libm) */
        (void*)sin,     (void*)cos,     (void*)tan,     (void*)sqrt,
        (void*)pow,     (void*)exp,     (void*)log,     (void*)log10,
        (void*)floor,   (void*)ceil,    (void*)fabs,    (void*)fmod,
        (void*)atan2,   (void*)hypot,
    };
    size_t n = sizeof(tab) / sizeof(tab[0]);
    for (size_t i = 0; i < n; i++)
        g_sink += (unsigned long)(uintptr_t)tab[i];
}

static void relay_init(void)
{
    memset(&g_cfg, 0, sizeof g_cfg);
    const char *ep = getenv("RELAY_ENDPOINT");
    if (ep)
        strncpy(g_cfg.endpoint, ep, sizeof g_cfg.endpoint - 1);
    else
        strncpy(g_cfg.endpoint, "field-bus.local", sizeof g_cfg.endpoint - 1);
    g_cfg.port = 9000;
    g_cfg.verbose = 0;
    g_cfg.seq = 0;
    srand((unsigned)time(NULL));
    load_relay_extensions();
}

static void relay_log(const char *who, const char *msg)
{
    time_t now = time(NULL);
    char ts[64];
    struct tm *lt = localtime(&now);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S", lt);
    fprintf(stderr, "[%s] %s: %s\n", ts, who, msg);
}

/* Opcode dispatch.  The PING/STAT/ECHO opcodes are benign; the diagnostic
 * opcode RUNDIAG assembles a maintenance command from request bytes and hands
 * it to the shell — the reachable command-execution path the brief asks about. */
static int handle_request(char *line)
{
    char op[16] = {0};
    char arg[256] = {0};

    /* request wire format:  "<OP> <arg...>" */
    if (sscanf(line, "%15s %255[^\n]", op, arg) < 1)
        return -1;
    g_cfg.seq++;

    for (char *p = op; *p; p++)
        *p = (char)toupper((unsigned char)*p);

    if (strcmp(op, "PING") == 0) {
        puts("PONG");
        return 0;
    }
    if (strcmp(op, "STAT") == 0) {
        printf("seq=%ld endpoint=%s port=%d\n",
               g_cfg.seq, g_cfg.endpoint, g_cfg.port);
        return 0;
    }
    if (strcmp(op, "ECHO") == 0) {
        puts(arg);
        return 0;
    }
    if (strcmp(op, "RUNDIAG") == 0) {
        /* maintenance hook: run a diagnostic helper named in the request */
        char cmd[320];
        snprintf(cmd, sizeof cmd, "/usr/libexec/mitis/diag-%s.sh", arg);
        relay_log("diag", cmd);
        return system(cmd);          /* <-- reachable system() sink */
    }

    relay_log("dispatch", "unknown opcode");
    return -1;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    relay_init();
    relay_log("relayd", "Mitis EdgeRelay relay daemon starting");

    char line[512];
    while (fgets(line, sizeof line, stdin)) {
        if (line[0] == '\n' || line[0] == '\0')
            continue;
        handle_request(line);
    }

    relay_log("relayd", "shutting down");
    /* fold the accumulator so the extension table cannot be optimized away */
    return (int)(g_sink & 0);
}
