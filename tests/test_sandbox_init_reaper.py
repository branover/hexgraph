"""The sandbox runs a real PID 1 (`docker run --init` → tini) that REAPS orphaned
children, so a long fuzzing campaign can't die from PID exhaustion.

Background: every sandbox container's command is `python3 <probe> ...`, so WITHOUT
`--init` the probe's python is PID 1 — and a PID-1 process does not reap reparented
orphans. libFuzzer's `-fork=1` / AFL's forkserver kill child fuzzers hard (an ASan
abort, or the cgroup OOM-killer) before the child reaps ITS OWN grandchildren (the
`llvm-symbolizer` ASan spawns to symbolize a crash). Those grandchildren reparent to
PID 1 and, unreaped, accumulate as ZOMBIES until they exhaust `--pids-limit` and
`fork()` starts returning EAGAIN — the long-observed "fragile forkserver under the
hardened sandbox" that made campaigns finalize `degraded`. `--init` (tini) reaps them.

These tests lock that:
  * the flag is UNCONDITIONALLY present (offline, no Docker), and
  * the REAL hardened container actually survives heavy orphan/zombie pressure that,
    without the reaper, exhausts the PID table (Docker-gated).
"""

import os
import subprocess
import textwrap

import pytest

from hexgraph.sandbox import runner as R

from conftest import SANDBOX_READY


# ── offline: the --init flag is an unconditional hardening invariant ─────────────────

def _hardening(**over):
    kw = dict(allow_network=False, net_container=None, resources=R.ResourceSpec(),
              secret=False)
    kw.update(over)
    return R.SandboxRunner(image="x")._hardening_args(**kw)


def test_init_reaper_flag_is_unconditional():
    """`--init` is present for EVERY container shape — like --cap-drop/--read-only it is a
    security/robustness invariant a ResourceSpec or network tier never removes."""
    shapes = [
        {},
        {"allow_network": True, "net_container": None},          # egress tier
        {"allow_network": True, "net_container": "rehost-x"},    # joined netns
        {"secret": True},                                         # channel secret
        {"disable_aslr": True},                                   # ASan source-fuzz path
        {"resources": R.ResourceSpec(unconstrained=True)},        # ceilings dropped
        {"resources": R.ResourceSpec(pids=4096, mem="8g")},       # raised ceilings
    ]
    for shape in shapes:
        args = _hardening(**shape)
        assert "--init" in args, f"--init missing for shape={shape}"


def test_init_is_a_docker_run_flag_before_the_image():
    """A `docker run` flag must sit in the hardening args (which precede the image +
    command in both run_probe and start_detached), not be tacked on after — otherwise
    Docker would treat it as a container argument."""
    args = _hardening()
    # `_hardening_args` returns ONLY pre-image flags; presence here guarantees correct
    # placement (run_probe/start_detached append `image, "python3", probe` afterwards).
    assert "--init" in args


# ── Docker-gated: the reaper actually prevents PID-table exhaustion ──────────────────

# A faithful stand-in for the libFuzzer/AFL forkserver under crash load: a parent that
# reaps its DIRECT child (as the forkserver does) while each child orphans a grandchild
# that reparents to PID 1. Without a reaping PID 1 the grandchildren pile up as zombies
# and `fork()` eventually fails with EAGAIN under `--pids-limit`. With `--init`, tini
# reaps them and every iteration succeeds. Prints a single summary line and exits
# nonzero if ANY fork failed or ANY zombie was left behind.
_ZOMBIE_PRESSURE = textwrap.dedent(
    """
    import os, sys, time

    def zombies():
        n = 0
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                st = open('/proc/%s/stat' % pid).read()
                if st.split(') ', 1)[1].split(' ', 1)[0] == 'Z':
                    n += 1
            except OSError:
                pass
        return n

    ITERS = 600
    fork_failures = 0
    for i in range(ITERS):
        try:
            pid = os.fork()
        except OSError:
            fork_failures += 1
            continue
        if pid == 0:
            # child: orphan a grandchild (reparents to PID 1), then exit WITHOUT reaping it
            try:
                gp = os.fork()
            except OSError:
                os._exit(0)
            if gp == 0:
                os._exit(0)        # grandchild -> orphan
            os._exit(0)            # child exits, leaving the grandchild for PID 1 to reap
        else:
            os.waitpid(pid, 0)     # the forkserver reaps its OWN direct child
    time.sleep(0.5)                # let the last orphans reparent + (hopefully) get reaped
    print("SUMMARY fork_failures=%d leftover_zombies=%d" % (fork_failures, zombies()))
    sys.exit(1 if (fork_failures or zombies()) else 0)
    """
)


@pytest.mark.skipif(not SANDBOX_READY, reason="requires Docker + the hexgraph-sandbox image")
def test_forkserver_survives_pid_pressure_under_real_hardening():
    """Run the EXACT hardened docker invocation HexGraph generates (with `--init`) on a
    workload that orphans hundreds of children under a tight `--pids-limit`. The reaper
    must keep the PID table clear: zero leftover zombies, zero `fork()` EAGAIN. Without
    `--init` this same workload exhausts the pids cap and the run reports failures —
    i.e. this test fails closed if the reaper is ever removed."""
    from hexgraph.sandbox.runner import sandbox_image

    runner = R.SandboxRunner(image=sandbox_image())
    # A tight pids cap so the test is fast + decisive: 600 orphaning iterations against
    # ~96 pids floods the table within seconds absent reaping (empirically ~60 zombies
    # exhaust a 64-pid cap), while a reaped run never climbs above a handful of live pids.
    resources = R.ResourceSpec(pids=96, mem="1g", cpus=1.0)
    cmd = [
        "docker", "run", "--rm",
        *runner._hardening_args(allow_network=False, net_container=None,
                                resources=resources, secret=False),
        sandbox_image(), "python3", "-c", _ZOMBIE_PRESSURE,
    ]
    assert "--init" in cmd, "the hardened invocation must carry the reaper"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = (proc.stdout or "") + (proc.stderr or "")
    assert "SUMMARY" in out, f"workload did not complete (rc={proc.returncode}): {out[-500:]}"
    assert proc.returncode == 0, (
        f"the reaper failed to keep the PID table clear under load: {out[-500:]}"
    )
    assert "leftover_zombies=0" in out and "fork_failures=0" in out, out[-500:]
