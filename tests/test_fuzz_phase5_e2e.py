"""Docker-gated end-to-end proof of Phase 5 — binary-only (AFL++ qemu-mode) + NETWORK
(boofuzz live-socket) + desock fuzzing in the dedicated hexgraph-fuzz image.

The NETWORK test is the one the blind-network-fuzz battle test leans on: a tiny vulnerable
TCP service with a planted protocol-parsing bug runs in a sidecar container; a boofuzz
campaign JOINS that container's netns (the rehost-composition path) and fuzzes it; the
service dies on a long/malformed message; the reaper ingests the crash as a fuzz_crash
finding (input_reachable/dynamic) with a re-runnable crashing message; and that reproducer
RE-VERIFIES by being re-sent over the live socket + a liveness oracle.

Skips cleanly without Docker + the hexgraph-fuzz image (build a private tag and set
HEXGRAPH_FUZZ_IMAGE for a worktree).
"""

import json
import os
import subprocess
import tempfile
import time
import uuid

import pytest

from conftest import FUZZ_IMAGE_READY


def _fuzz_image():
    return os.environ.get("HEXGRAPH_FUZZ_IMAGE", "hexgraph-fuzz:latest")


def _compile_in_image(src_text: str, out_name: str, host_dir: str, *, cflags=None,
                      cc="clang", env=None) -> str:
    """Compile a C source to a host ELF using the fuzz image's compiler (so the binary is
    runnable in the sandbox). `cc` can be afl-clang-fast for an instrumented build. Returns
    the host path."""
    src = os.path.join(host_dir, f"{out_name}.c")
    open(src, "w").write(src_text)
    flags = cflags or ["-O0", "-g"]
    env_args = []
    for k, v in (env or {}).items():
        env_args += ["-e", f"{k}={v}"]
    cmd = ["docker", "run", "--rm", *env_args, "-v", f"{host_dir}:/work:rw", "-w", "/work",
           _fuzz_image(), cc, *flags, f"{out_name}.c", "-o", out_name]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, f"compile failed: {r.stderr}"
    return os.path.join(host_dir, out_name)


# ── Binary-only: AFL++ qemu-mode finds a planted crash in a STRIPPED native ELF ───

# Reads a file (argv[1]); a specific 4-byte magic reaches a planted NULL-deref that segfaults
# DETERMINISTICALLY under qemu-mode with NO instrumentation. AFL++ qemu-mode gets coverage
# from QEMU TCG and, steered by the dictionary + a near-miss seed, flips the bytes to "BUG!".
BIN_C = r"""
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    unsigned char in[256]; size_t n = fread(in, 1, sizeof(in), f); fclose(f);
    if (n < 4) return 0;
    if (in[0] == 'B' && in[1] == 'U' && in[2] == 'G' && in[3] == '!') {
        int *p = NULL; *p = 0x41414141;   /* planted SIGSEGV behind the magic gate */
    }
    return 0;
}
"""


@pytest.mark.skipif(not FUZZ_IMAGE_READY,
                    reason="requires Docker + the hexgraph-fuzz image")
def test_binary_only_qemu_mode_finds_planted_crash(hg_home):
    from hexgraph.db.models import FuzzArtifact, FuzzCampaign, Target, TargetKind
    from hexgraph.db.session import session_scope
    from hexgraph.engine import campaigns as C
    from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
    from hexgraph.engine.ingest import create_project
    from hexgraph import settings as st

    st.update_settings({"features.fuzzing.enabled": True, "features.poc.enabled": True})
    th = tempfile.mkdtemp(prefix="hexgraph-bin-e2e-")
    # NO ASan: qemu-mode fuzzes an UNINSTRUMENTED binary (coverage from QEMU TCG, crash
    # detection from the SIGSEGV). ASan's shadow memory is incompatible with qemu-user.
    binpath = _compile_in_image(BIN_C, "vuln", th, cflags=["-O0", "-g"])
    seed = os.path.join(th, "seed")
    open(seed, "wb").write(b"BUGx")  # a near-miss (one byte off the magic), does NOT crash

    with session_scope() as s:
        p = create_project(s, name="bin-e2e")
        t = Target(project_id=p.id, name="vuln", path=binpath, kind=TargetKind.executable)
        s.add(t); s.flush()
        spec = FuzzCampaignSpec(target_id=t.id, surface="binary_only", engine="qemu",
                                target_binary=binpath, seeds=[seed],
                                dictionary=["BUG!"], max_total_time=90, max_crashes=3)
        cid = C.start_campaign(s, p, t, spec=spec).id
        assert s.get(FuzzCampaign, cid).engine == "qemu"

    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        with session_scope() as s:
            C.reap_campaign(s, s.get(FuzzCampaign, cid))
            c = s.get(FuzzCampaign, cid)
            if c.status in ("completed", "failed"):
                break
        time.sleep(4)

    with session_scope() as s:
        c = s.get(FuzzCampaign, cid)
        arts = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).all()
        assert arts, f"qemu-mode found no crash (status={c.status}, err={c.error})"
        a = arts[0]
        assert a.content_cas and a.finding_id and a.dedup_key


# ── NETWORK: boofuzz drops a live vulnerable TCP service (the battle-test path) ───

# A trivial line server with a stack overflow on a long line — a classic protocol-parser
# bug. It loops accept()ing connections, reads a line into a tiny buffer (unbounded), and
# crashes (SIGSEGV/stack-smash) on a long line. Built with -fstack-protector so a long
# line aborts the process deterministically.
SERVER_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
static void handle(int c) {
    char line[64];
    char big[8192];
    int n = recv(c, big, sizeof(big) - 1, 0);
    if (n <= 0) return;
    big[n] = 0;
    strcpy(line, big);                 /* stack buffer overflow on a long line */
    send(c, line, strlen(line), 0);
}
int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9999;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(port);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) return 1;
    listen(s, 16);
    for (;;) { int c = accept(s, 0, 0); if (c < 0) continue; handle(c); close(c); }
    return 0;
}
"""


@pytest.mark.skipif(not FUZZ_IMAGE_READY,
                    reason="requires Docker + the hexgraph-fuzz image")
def test_network_boofuzz_drops_live_service_and_reverifies(hg_home):
    from hexgraph.db.models import (EgressEvent, Finding, FuzzArtifact, FuzzCampaign,
                                    Target, TargetKind)
    from hexgraph.db.session import session_scope
    from hexgraph.engine import campaigns as C
    from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
    from hexgraph.engine.ingest import create_project
    from hexgraph import settings as st

    # Network fuzzing rides the EXISTING local-network tier — features.network, no new gate.
    st.update_settings({"features.network.enabled": True})
    th = tempfile.mkdtemp(prefix="hexgraph-net-e2e-")
    # -fstack-protector → a long line aborts (deterministic death); -static so the sidecar
    # (a bare image) can run it with no libs.
    srv = _compile_in_image(SERVER_C, "vuln_server", th,
                            cflags=["-O0", "-g", "-static", "-fstack-protector-all"])
    port = 9999
    sidecar = f"hexgraph-vulnsrv-{uuid.uuid4().hex[:8]}"

    def _start_server():
        subprocess.run(["docker", "rm", "-f", sidecar], capture_output=True, timeout=30)
        # A persistent netns-holder that SUPERVISES the server with a ~3s restart delay
        # (mimics a rehosted device: the emulator container/netns stays up even when the
        # device daemon crashes + is respawned by init). The 3s down window is reliably
        # caught by the liveness oracle (fresh connect refused) — the unforgeable death
        # signal — while the netns survives so the probe can keep re-attaching.
        r = subprocess.run(
            ["docker", "run", "-d", "--name", sidecar,
             "-v", f"{th}:/srv:ro", "--entrypoint", "/bin/sh",
             _fuzz_image(), "-c",
             f"while true; do /srv/vuln_server {port}; sleep 3; done"],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        time.sleep(2)  # let it bind

    _start_server()
    try:
        with session_scope() as s:
            p = create_project(s, name="net-e2e")
            # A web_app surface whose channel points at the sidecar; the campaign joins the
            # sidecar's netns (net_container) so 127.0.0.1:port reaches the server — exactly
            # the rehost-composition path (an emulator container netns join).
            t = Target(project_id=p.id, name=f"vuln_server:{port}", path="",
                       kind=TargetKind.web_app,
                       metadata_json={"channel": {"kind": "tcp", "host": "127.0.0.1",
                                                  "port": port,
                                                  "rehost": {"ip": "127.0.0.1",
                                                             "container": sidecar}}})
            s.add(t); s.flush()
            spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz",
                                    max_total_time=60, max_crashes=3)
            cid = C.start_campaign(s, p, t, spec=spec).id
            c = s.get(FuzzCampaign, cid)
            assert c.engine == "boofuzz" and c.status == "running"
            # the launch was audited as an ALLOWED egress to the bounded local dest
            ev = s.query(EgressEvent).filter(EgressEvent.project_id == p.id,
                                             EgressEvent.allowed.is_(True),
                                             EgressEvent.tool == "boofuzz").all()
            assert ev and ev[0].dest == f"127.0.0.1:{port}"

        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            with session_scope() as s:
                C.reap_campaign(s, s.get(FuzzCampaign, cid))
                c = s.get(FuzzCampaign, cid)
                if c.status in ("completed", "failed"):
                    break
            time.sleep(4)

        with session_scope() as s:
            c = s.get(FuzzCampaign, cid)
            arts = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).all()
            assert arts, f"boofuzz found no service crash (status={c.status}, err={c.error})"
            a = arts[0]
            assert a.finding_id and a.content_cas
            f = s.get(Finding, a.finding_id)
            asr = (f.evidence_json["extra"]).get("assurance")
            # a live-service death reached through the real socket = input_reachable/dynamic
            assert asr["standard"] == "input_reachable" and asr["method"] == "dynamic"
            nr = f.evidence_json["extra"]["fuzz"]["net_reproducer"]
            assert nr and nr["payload_b64"]

        # RE-VERIFY: the supervised server has respawned; re-send the crashing message over
        # the live socket — it dies again, the liveness oracle confirms it goes DOWN.
        time.sleep(4)  # let the supervisor respawn the server after the campaign's kills
        with session_scope() as s:
            a = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).first()
            res = C.verify_artifact(s, a)
            assert res.get("verified") is True, res
            assert res["assurance"]["standard"] == "input_reachable"
    finally:
        subprocess.run(["docker", "rm", "-f", sidecar], capture_output=True, timeout=30)


# ── desock: AFL++ coverage-fuzzes a LOCAL server binary with --network none ───────

# A SINGLE-SHOT server (accept → handle one connection → exit) — the right shape for desock
# under AFL (the program must terminate per input). Same stack-overflow on a long line.
DESOCK_SERVER_C = r"""
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(9999);
    bind(s, (struct sockaddr*)&a, sizeof(a)); listen(s, 1);
    int c = accept(s, 0, 0);              /* desock: this fd is backed by stdin */
    char line[64], big[8192];
    int n = recv(c, big, sizeof(big) - 1, 0);
    if (n <= 0) return 0;
    big[n] = 0;
    strcpy(line, big);                    /* stack buffer overflow on a long line */
    write(c, line, strlen(line));
    return 0;
}
"""


@pytest.mark.skipif(not FUZZ_IMAGE_READY,
                    reason="requires Docker + the hexgraph-fuzz image")
def test_desock_afl_fuzzes_local_server_no_network(hg_home):
    from hexgraph.db.models import FuzzArtifact, FuzzCampaign, Target, TargetKind
    from hexgraph.db.session import session_scope
    from hexgraph.engine import campaigns as C
    from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
    from hexgraph.engine.ingest import create_project
    from hexgraph import settings as st

    st.update_settings({"features.fuzzing.enabled": True, "features.poc.enabled": True})
    th = tempfile.mkdtemp(prefix="hexgraph-desock-e2e-")
    # A SINGLE-SHOT vulnerable line server (accept→handle→exit), compiled INSTRUMENTED with
    # afl-clang-fast + ASan so AFL gets real coverage and a clean crash report. desock
    # (AFL_PRELOAD) turns its accept()/recv() socket into stdin → AFL feeds it with
    # --network none (no real networking — the static-by-default posture holds).
    srv = _compile_in_image(DESOCK_SERVER_C, "vuln_server", th, cc="afl-clang-fast",
                            cflags=["-O0", "-g", "-fstack-protector-all"],
                            env={"AFL_USE_ASAN": "1"})
    seed = os.path.join(th, "seed")
    open(seed, "wb").write(b"hello\n")

    with session_scope() as s:
        p = create_project(s, name="desock-e2e")
        t = Target(project_id=p.id, name="vuln_server", path=srv, kind=TargetKind.executable)
        s.add(t); s.flush()
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="desock",
                                target_binary=srv, seeds=[seed], port=9999,
                                max_total_time=90, max_crashes=3)
        cid = C.start_campaign(s, p, t, spec=spec).id
        assert s.get(FuzzCampaign, cid).engine == "desock"

    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        with session_scope() as s:
            C.reap_campaign(s, s.get(FuzzCampaign, cid))
            c = s.get(FuzzCampaign, cid)
            if c.status in ("completed", "failed"):
                break
        time.sleep(4)

    with session_scope() as s:
        c = s.get(FuzzCampaign, cid)
        arts = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).all()
        # desock requires preeny in the image; if absent, the probe degrades to file-input
        # qemu-mode (still coverage-guided) — either way it should reach the overflow.
        assert arts, f"desock/AFL found no crash (status={c.status}, err={c.error})"
        assert arts[0].content_cas and arts[0].finding_id
