/*
 * eventlogd — event logger for the Halcyon HNVR-8 network video recorder.
 * Reads one event line from the control socket (stdin here) and writes it to the
 * system log, optionally tagging privileged events with the stream key.
 * Analysis fixture — never run outside the sandbox.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Write one event to the log. The stream key is passed so the logger CAN tag
 * privileged events with it; the intended call uses a FIXED format like
 * printf("%s", line). BUG: `tmpl` comes from the request, so an attacker
 * controls the printf format string (CWE-134) and can disclose the key. */
static void write_event(const char *tmpl, const char *streamkey) {
    fputs("[evt] ", stdout);
    printf(tmpl, streamkey);          /* attacker-controlled format string */
    fputc('\n', stdout);
}

/* Return the value of "KEY=" at the start of the request line, else NULL. */
static const char *field(char *line, const char *key) {
    size_t kn = strlen(key);
    if (strncmp(line, key, kn) == 0 && line[kn] == '=')
        return line + kn + 1;
    return NULL;
}

int main(void) {
    setbuf(stdout, NULL);
    const char *streamkey = getenv("STREAM_KEY");   /* per-session secret */
    if (!streamkey) streamkey = "unset";
    char line[512];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\r\n")] = '\0';
    const char *tmpl = field(line, "TMPL");
    if (!tmpl) tmpl = "event received";
    write_event(tmpl, streamkey);
    return 0;
}
