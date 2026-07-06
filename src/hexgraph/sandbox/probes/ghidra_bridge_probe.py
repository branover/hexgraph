#!/usr/bin/env python3
"""Entrypoint for a persistent Ghidra bridge container (engine.re.bridge).

`start_detached` runs this as `python3 /opt/hexgraph/ghidra_bridge_probe.py /artifact` in a
long-lived (`docker run -d`) container. It opens the target's WARM slot with
`analyzeHeadless -process` (no -import, no re-analysis) and runs `ghidra_bridge_serve.py` as the
postScript, then `execvp`s so analyzeHeadless REPLACES this process and becomes the container's
long-lived PID: the harness blocks (`server.run()`), keeping the JVM + the opened program resident
to serve ghidra_bridge RPC calls. So repeated re_decompile/re_xrefs/... for the target skip the
per-call project open the headless path pays every time (~15s on a 6GB project).

Importing `ghidra_probe` pins every writable Ghidra/Java path at the /scratch tmpfs (its
module-level env setup) and reuses the exact warm-invocation helpers, so the bridge open matches
the headless warm path byte-for-byte (same project name, program name, -noanalysis).
"""
import os
import sys

import ghidra_probe as gp  # module import pins HOME/TMPDIR/XDG_*/_JAVA_OPTIONS at /scratch


def main() -> int:
    artifact = sys.argv[1] if len(sys.argv) > 1 else "/artifact"
    hl = gp._find_headless()
    if not hl:
        sys.stderr.write("ghidra_bridge_probe: analyzeHeadless not found "
                         "(build the sandbox image WITH_GHIDRA=1)\n")
        return 3
    proj_dir = os.path.join(gp.PROJECT_MOUNT, "project")
    if not (os.path.isdir(proj_dir) and os.listdir(proj_dir)):
        sys.stderr.write("ghidra_bridge_probe: no warm project at %s "
                         "(run re_analyze first)\n" % proj_dir)
        return 4
    prog = gp._program_name(artifact)
    scripts = os.path.dirname(os.path.abspath(__file__))  # /opt/hexgraph (the mounted probes)
    # WARM open (matches ghidra_probe's -process path) + the bridge-server harness as the postScript.
    cmd = [hl, proj_dir, gp.PROJECT_NAME, "-process", prog, "-noanalysis",
           "-scriptPath", scripts, "-postScript", "ghidra_bridge_serve.py"]
    sys.stderr.write("ghidra_bridge_probe: exec %s\n" % " ".join(cmd))
    sys.stderr.flush()
    # Replace this process: analyzeHeadless becomes the container's long-lived PID; the harness
    # blocks in-thread, so the container stays up until stop_detached kills it.
    os.execvp(cmd[0], cmd)
    return 0  # unreachable (execvp replaces the image)


if __name__ == "__main__":
    raise SystemExit(main())
