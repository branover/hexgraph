"""Seed a rich, deterministic "showcase" project on the MOCK backend ($0, offline).

The goal is ONE project that exercises as many of HexGraph's graph visuals and
features as possible — for the README hero shots and the per-feature doc captures —
while staying reproducible: a fixed RNG seed + stable structure so a re-seed +
re-capture reproduces the same screenshots as the UI evolves.

What it builds (a plausible consumer-router engagement):

  Targets
    • a FIRMWARE image (real fixture bytes) with a browsable unpacked filesystem
      and two unpacked-FS CHILDREN: sbin/httpd (MIPS executable) + lib/libupnp.so
    • a standalone BINARY (a config daemon)
    • a WEB_APP surface (the router admin UI) described by a route spec
    • a SERVICE (raw-TCP socket) surface — a custom UPnP/telnet-ish daemon
  Source
    • a managed SOURCE TREE — a small C lib (httpd.c/upnp.c) + a fuzz harness —
      whose file names match the mock fuzzer's coverage map so coverage shading
      and the symbolized crash stack link to real source lines.
  Graph
    • typed NODES: function / string / sink / socket / endpoint / param
    • a WIDE edge variety: contains, calls, routes_to, listens_on, connects_to,
      built_from, located_in, instrumented_build_of, links_against, taints,
      bypasses, related_to, about — colorful but curated for legibility.
  Findings (spanning finding_type + the assurance ladder)
    • a VERIFIED PoC (command-injection, input_reachable/dynamic) with a repro spec
    • a static memory-safety vuln (code_present/static — the floor)
    • an argued-reachable vuln (input_reachable/static)
    • a recon finding, an info-leak, an auth bypass
    • a real, FINISHED mock fuzz campaign (run via the offline MockFuzzer) →
      crash artifacts (dedup group + exploitability + minimized reproducer) +
      a per-line coverage map + a fuzz_crash finding (code_present/dynamic).
  Audit
    • a few EgressEvent rows (allowed + one denied) so the egress audit view renders.

Run via `just showcase` (sets HEXGRAPH_FUZZER=mock + a fresh HEXGRAPH_HOME) or
directly. Deterministic: pass --reset to wipe the project first; idempotent on the
project name otherwise.
"""

from __future__ import annotations

import argparse
import os
import sys

# Mock everything, offline, zero token spend. Set BEFORE importing hexgraph so the
# campaign engine selects the offline MockFuzzer.
os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")
os.environ.setdefault("HEXGRAPH_FUZZER", "mock")
# The campaign machinery never executes target bytes in mock mode, but the policy
# gate still wants fuzzing enabled — we flip it in settings below too.

from hexgraph.paths import repo_root  # noqa: E402

PROJECT_NAME = "Acme R7000 — router firmware engagement"


def _fixtures():
    return repo_root() / "tests" / "fixtures"


def _step(msg: str) -> None:
    print(f"\033[36m▶\033[0m {msg}")


# ── A small, realistic C library + harness (matches the mock coverage map keys) ────
HTTPD_C = """\
/* httpd.c — the router's embedded web server (trimmed for the showcase). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Parse one CGI parameter out of the query string. */
static char *get_param(const char *qs, const char *key) {
    static char val[256];
    const char *p = strstr(qs, key);
    if (!p) return NULL;
    p += strlen(key) + 1;          /* skip "key=" */
    size_t i = 0;
    while (*p && *p != '&' && i < sizeof(val) - 1)
        val[i++] = *p++;
    val[i] = '\\0';
    return val;
}

/* The /cgi-bin/ping handler — reachable unauthenticated from the LAN. */
int cgi_handler(const char *query) {
    char cmd[128];
    char *host = get_param(query, "host");          /* attacker-controlled */
    if (!host) return 1;
    /* BUG: host is concatenated straight into a shell command (CWE-78). */
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    return system(cmd);                              /* command injection sink */
}

int diagnostics(const char *query) {
    char buf[64];
    char *tgt = get_param(query, "target");
    strcpy(buf, tgt);                                /* BUG: unbounded copy (CWE-120) */
    return cgi_handler(buf);
}

int main(int argc, char **argv) {
    if (argc > 1) return diagnostics(argv[1]);
    return 0;
}
"""

UPNP_C = """\
/* upnp.c — the UPnP/SSDP listener bound on udp/1900 + a control socket on tcp/5000. */
#include <string.h>

int ssdp_dispatch(const char *msg, unsigned len) {
    char service[128];
    /* BUG: copies a length field straight from the packet (CWE-787). */
    memcpy(service, msg + 8, len);
    return service[0];
}

int upnp_control(const char *soap) {
    return strlen(soap);
}
"""

HARNESS_C = """\
/* fuzz_cgi.c — a libFuzzer/AFL harness driving the CGI parser directly. */
#include <stddef.h>
#include <stdint.h>

extern int cgi_handler(const char *query);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char q[512];
    size_t n = size < sizeof(q) - 1 ? size : sizeof(q) - 1;
    __builtin_memcpy(q, data, n);
    q[n] = 0;
    return cgi_handler(q);
}
"""

# Files inside the firmware's "unpacked" filesystem (manifest only — browsable in the
# detail panel; the two ELFs become child targets).
FS_FILES = [
    {"rel": "sbin/httpd", "size": 81_232, "is_elf": True},
    {"rel": "lib/libupnp.so", "size": 45_880, "is_elf": True},
    {"rel": "lib/libc.so.0", "size": 512_400, "is_elf": True},
    {"rel": "etc/passwd", "size": 421, "is_elf": False},
    {"rel": "etc/shadow", "size": 388, "is_elf": False},
    {"rel": "etc/config/network", "size": 1_204, "is_elf": False},
    {"rel": "etc/init.d/httpd", "size": 642, "is_elf": False},
    {"rel": "www/index.html", "size": 3_980, "is_elf": False},
    {"rel": "www/cgi-bin/ping", "size": 2_104, "is_elf": False},
    {"rel": "usr/sbin/telnetd", "size": 28_400, "is_elf": True},
    {"rel": "usr/sbin/upnpd", "size": 33_120, "is_elf": True},
]

# The router admin UI's route spec (offline — no network). `handler` names resolve to
# function nodes in the httpd binary via routes_to edges (the static↔dynamic bridge).
ENDPOINTS = [
    {"method": "POST", "path": "/cgi-bin/ping", "handler": "cgi_handler", "auth": "none",
     "params": ["host", "count"], "status": 200},
    {"method": "GET", "path": "/cgi-bin/diagnostics", "handler": "diagnostics", "auth": "none",
     "params": ["target"], "status": 200},
    {"method": "POST", "path": "/api/login", "auth": "none", "params": ["user", "password"], "status": 200},
    {"method": "GET", "path": "/api/system/status", "handler": "upnp_control", "auth": "session",
     "params": [], "status": 200},
    {"method": "GET", "path": "/api/devices", "auth": "session", "params": ["page"], "status": 200},
]


def _classify(target, *, kind, fmt=None, arch=None, extra=None):
    """Stamp recon-style classification onto a target (we don't run the sandbox)."""
    from hexgraph.db.models import TargetKind

    target.kind = TargetKind(kind)
    if fmt:
        target.format = fmt
    if arch:
        target.arch = arch
    meta = dict(target.metadata_json or {})
    if extra:
        meta.update(extra)
    target.metadata_json = meta


def seed(session, *, reset: bool) -> dict:
    from hexgraph.db.models import (
        Edge, EdgeType, Finding as FRow, FuzzCampaign, Node, NodeType, Project, Target,
    )
    from hexgraph.engine import assurance as A
    from hexgraph.engine.audit import record_egress
    from hexgraph.engine.authoring import create_edge, create_socket
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.filesystem import persistent_base, record_manifest
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
    from hexgraph.engine.ingest import create_project, ingest_file
    from hexgraph.engine.nodes import get_or_create_node, materialize_function
    from hexgraph.engine.source import (
        create_source_tree, link_finding_to_source, materialize_source_file, write_source_file,
    )
    from hexgraph.engine.surfaces import register_socket_target, register_web_surface, run_surface_recon
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Evidence, Finding, FollowupSuggestion

    fixtures = _fixtures()
    httpd_bytes = fixtures / "vuln_httpd"
    lib_bytes = fixtures / "libupnp.so"
    fw_bytes = fixtures / "synthetic_fw.bin"
    for f in (httpd_bytes, lib_bytes, fw_bytes):
        if not f.exists():
            print(f"missing fixture {f.name}; run `just fixtures` first.", file=sys.stderr)
            raise SystemExit(2)

    # Idempotency: optionally wipe a prior showcase project of the same name.
    existing = session.query(Project).filter(Project.name == PROJECT_NAME).all()
    if existing and reset:
        from hexgraph.engine.removal import delete_project
        for p in existing:
            delete_project(session, p.id)
        session.flush()
        existing = []
    if existing:
        return {"project_id": existing[0].id, "reused": True}

    _step("Create project (mock backend)")
    project = create_project(session, name=PROJECT_NAME, llm_backend="mock")
    pid = project.id

    # ── Targets ────────────────────────────────────────────────────────────────────
    _step("Ingest firmware image + unpacked-FS children + standalone binary")
    fw = ingest_file(session, project, str(fw_bytes), name="acme_r7000_v1.0.4.chk")
    _classify(fw, kind="firmware_image", fmt="TRX/uImage → squashfs", arch="mipsel",
              extra={"vendor": "Acme", "model": "R7000", "version": "1.0.4"})

    # The unpacked filesystem (manifest only) so the FS browser renders. Lay the bytes
    # of the two ELF children on disk under the firmware's unpacked root so they're real.
    fs_root = persistent_base(project, fw.id) / "squashfs-root"
    (fs_root / "sbin").mkdir(parents=True, exist_ok=True)
    (fs_root / "lib").mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(httpd_bytes, fs_root / "sbin" / "httpd")
    shutil.copy2(lib_bytes, fs_root / "lib" / "libupnp.so")

    httpd = ingest_file(session, project, str(httpd_bytes), name="sbin/httpd", parent=fw)
    _classify(httpd, kind="executable", fmt="ELF", arch="mipsel",
              extra={"mitigations": {"nx": True, "pie": False, "canary": False, "relro": "partial"},
                     "imports": ["system", "strcpy", "recv", "snprintf"]})
    lib = ingest_file(session, project, str(lib_bytes), name="lib/libupnp.so", parent=fw)
    _classify(lib, kind="shared_library", fmt="ELF", arch="mipsel",
              extra={"mitigations": {"nx": True, "pie": True, "canary": True, "relro": "full"}})

    # Record the firmware filesystem manifest, marking the two extracted ELFs as added.
    fs_manifest = []
    for f in FS_FILES:
        e = dict(f)
        if e["rel"] == "sbin/httpd":
            e["child_target_id"] = httpd.id
        elif e["rel"] == "lib/libupnp.so":
            e["child_target_id"] = lib.id
        fs_manifest.append(e)
    record_manifest(fw, method="binwalk -eM (squashfs/sasquatch)", root_rel="squashfs-root",
                    files=fs_manifest)

    # A standalone binary root (a config daemon shipped separately).
    daemon = ingest_file(session, project, str(lib_bytes), name="acmecfgd")
    _classify(daemon, kind="executable", fmt="ELF", arch="x86_64",
              extra={"mitigations": {"nx": True, "pie": True, "canary": True, "relro": "full"}})

    # ── Dynamic surfaces ────────────────────────────────────────────────────────────
    _step("Register web_app admin surface + a raw-TCP service surface")
    web = register_web_surface(session, project, "http://192.168.1.1", name="R7000 admin UI",
                               parent=fw, endpoints=ENDPOINTS)
    svc = register_socket_target(session, project, "192.168.1.1", 5000, transport="tcp",
                                 proto="upnp", name="upnpd control (tcp/5000)", parent=fw)

    # ── Source tree (a small C lib + a harness) ──────────────────────────────────────
    _step("Create source tree (C lib + fuzz harness)")
    tree = create_source_tree(session, project, name="acme-httpd (src)", origin="scratch")
    write_source_file(session, project, tree, "src/httpd.c", HTTPD_C, role="code")
    write_source_file(session, project, tree, "src/upnp.c", UPNP_C, role="code")
    write_source_file(session, project, tree, "fuzz/fuzz_cgi.c", HARNESS_C, role="harness")
    # The mock fuzzer's coverage map keys "target.c" — give it a real file to shade.
    write_source_file(session, project, tree, "target.c", HTTPD_C, role="code")
    # Link the source tree to the httpd binary it builds (target → source_tree).
    create_edge(session, project, src_kind="target", src_id=httpd.id,
                dst_kind="source_tree", dst_id=tree.id, type="built_from",
                attrs={"system": "make"})

    # ── Typed nodes (functions, strings, sink, socket) ───────────────────────────────
    _step("Materialize typed nodes (functions / strings / sink / socket) + edges")
    fns = {}
    for name, addr in [("cgi_handler", "0x401a40"), ("diagnostics", "0x401b10"),
                       ("get_param", "0x4018c0"), ("main", "0x401c00")]:
        fns[name] = materialize_function(session, project_id=pid, target_id=httpd.id,
                                         name=name, address=addr, created_by="recon")
    upnp_fns = {}
    for name, addr in [("ssdp_dispatch", "0x8a0"), ("upnp_control", "0x9c0")]:
        upnp_fns[name] = materialize_function(session, project_id=pid, target_id=lib.id,
                                             name=name, address=addr, created_by="recon")

    # A dangerous sink node + a couple of interesting strings.
    sink = get_or_create_node(session, project_id=pid, node_type=NodeType.sink, name="system",
                              target_id=httpd.id, address="0x402300",
                              attrs={"library": "libc", "danger": "command-exec"})
    get_or_create_node(session, project_id=pid, node_type=NodeType.string,
                       name="ping -c 1 %s", target_id=httpd.id,
                       content_hash=None, attrs={"value": "ping -c 1 %s"})
    get_or_create_node(session, project_id=pid, node_type=NodeType.string,
                       name="admin:$1$xyz$...", target_id=httpd.id,
                       attrs={"value": "admin:$1$xyz$abcdef0123456789:0:0:root:/:/bin/sh"})

    # Shared socket nodes (the firmware's network map). The service surface already made
    # the tcp/5000 socket; add the SSDP udp/1900 listener too.
    sock_ssdp = create_socket(session, project, kind="udp", port=1900, name="ssdp",
                              bind_addr="0.0.0.0")
    # Resolve the shared tcp/5000 socket node the service registration created.
    sock_ctrl = (session.query(Node)
                 .filter(Node.project_id == pid, Node.node_type == NodeType.socket.value,
                         Node.fq_name == "tcp:5000").first())

    # ── Edges: a wide, curated variety ───────────────────────────────────────────────
    # calls (with call_sites), taints (source→sink), bypasses, listens_on / connects_to,
    # links_against, instrumented_build_of, related_to. (contains/about/routes_to/built_from
    # are created by the helpers above.)
    add_edge(session, project_id=pid, src=("node", fns["main"].id), dst=("node", fns["diagnostics"].id),
             type=EdgeType.calls, origin="tool", confidence=0.9, attrs={"call_sites": ["0x401c1c"]})
    add_edge(session, project_id=pid, src=("node", fns["diagnostics"].id), dst=("node", fns["cgi_handler"].id),
             type=EdgeType.calls, origin="tool", confidence=0.9, attrs={"call_sites": ["0x401b48"]})
    add_edge(session, project_id=pid, src=("node", fns["cgi_handler"].id), dst=("node", fns["get_param"].id),
             type=EdgeType.calls, origin="tool", confidence=0.9, attrs={"call_sites": ["0x401a60", "0x401a8c"]})
    add_edge(session, project_id=pid, src=("node", fns["cgi_handler"].id), dst=("node", sink.id),
             type=EdgeType.calls, origin="tool", confidence=0.9, attrs={"call_sites": ["0x401ad0"]})
    # taints: get_param's return (attacker input) flows into the system() sink.
    add_edge(session, project_id=pid, src=("node", fns["get_param"].id), dst=("node", sink.id),
             type=EdgeType.taints, origin="llm", confidence=0.8,
             attrs={"via": "host param", "note": "query string → system()"})
    # listens_on / connects_to the shared sockets.
    if sock_ctrl is not None:
        add_edge(session, project_id=pid, src=("node", upnp_fns["upnp_control"].id),
                 dst=("node", sock_ctrl.id), type=EdgeType.listens_on, origin="tool",
                 confidence=0.9, attrs={"address": "0.0.0.0:5000", "backlog": 16})
    add_edge(session, project_id=pid, src=("node", upnp_fns["ssdp_dispatch"].id),
             dst=("node", sock_ssdp.id), type=EdgeType.listens_on, origin="tool",
             confidence=0.9, attrs={"address": "0.0.0.0:1900"})
    add_edge(session, project_id=pid, src=("node", fns["cgi_handler"].id),
             dst=("node", sock_ssdp.id), type=EdgeType.connects_to, origin="tool",
             confidence=0.6, attrs={"note": "M-SEARCH probe"})
    # links_against: httpd links the upnp lib.
    add_edge(session, project_id=pid, src=("target", httpd.id), dst=("target", lib.id),
             type=EdgeType.links_against, origin="tool", confidence=0.9)
    # routes_to handler in the lib (cross-binary): /api/system/status → upnp_control.
    add_edge(session, project_id=pid, src=("node", upnp_fns["upnp_control"].id),
             dst=("node", sink.id), type=EdgeType.references, origin="tool", confidence=0.5)

    # Materialise the web route spec into endpoint/param nodes + routes_to edges.
    run_surface_recon(session, project, web)

    # ── Findings (span finding_type + the assurance ladder) ──────────────────────────
    _step("Persist findings across types + the assurance ladder")

    def _task(target, ttype):
        return create_task(session, project=project, target_id=target.id, type=ttype, backend="mock")

    # 1) Recon finding on the firmware (info).
    persist_finding(session, project_id=pid, target_id=fw.id, task_id=_task(fw, "recon").id,
                    finding=Finding(
                        title="Firmware unpacked: 1 squashfs rootfs, 11 files, 5 ELF binaries",
                        severity="info", confidence="high", category="recon",
                        summary="binwalk recursive extraction recovered a MIPS little-endian rootfs; "
                                "httpd + libupnp + telnetd/upnpd are network-facing.",
                        reasoning="Recon classified the image and enumerated the extracted filesystem.",
                        evidence=Evidence(extra={"arch": "mipsel", "files": 11, "elf_binaries": 5})),
                    finding_type="recon")

    # 2) VERIFIED PoC — command injection, input_reachable/dynamic (the hero finding).
    poc_spec = {
        "transport": "web",
        "steps": [{"method": "POST", "path": "/cgi-bin/ping",
                   "params": {"host": "127.0.0.1; echo {{NONCE}}"}}],
        "oracle": {"type": "body_contains", "value": "{{NONCE}}"},
        "scope": "entrypoint", "precondition": "unauthenticated",
    }
    verification = {
        "verified": True,
        "detail": "triggered through the live deployed input boundary — the injected `echo` "
                  "of the unforgeable nonce appeared in the HTTP response body.",
        "nonce": "hx-9f3a2c7e",
        "exit_code": 0,
        "output": "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
                  "64 bytes from 127.0.0.1: seq=0 ttl=64 time=0.041 ms\n"
                  "hx-9f3a2c7e\n",
        "assurance": A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED,
                                 detail="triggered through the live deployed input boundary"),
    }
    f_poc = persist_finding(
        session, project_id=pid, target_id=web.id, task_id=_task(web, "poc").id,
        finding=Finding(
            title="Unauthenticated command injection in /cgi-bin/ping (host param)",
            severity="critical", confidence="high", category="command-injection",
            summary="The `host` query parameter is concatenated into a shell command run via "
                    "system(); an unauthenticated LAN attacker gains arbitrary command execution.",
            reasoning="cgi_handler() builds `ping -c 1 <host>` and passes it to system() with no "
                      "sanitization. A live PoC injected `; echo <nonce>` and the nonce appeared in "
                      "the response — reached and triggered end-to-end through the admin UI.",
            evidence=Evidence(
                function="cgi_handler", sink="system", file="/sbin/httpd", address="0x401ad0",
                reproducer="POST /cgi-bin/ping  host=127.0.0.1; echo VULN",
                extra={"poc": poc_spec, "verification": verification,
                       "assurance": verification["assurance"],
                       "repro_command": ["curl", "-s", "-X", "POST", "http://192.168.1.1/cgi-bin/ping",
                                         "--data-urlencode", "host=127.0.0.1; id"]}),
            suggested_followups=[
                FollowupSuggestion(task_type="pattern_sweep", label="Sweep siblings for the same system() sink",
                                   params={"sink": "system"}),
                FollowupSuggestion(task_type="reverse_engineering", label="Trace get_param() bounds in libupnp"),
            ]),
        status=__import__("hexgraph.db.models", fromlist=["FindingStatus"]).FindingStatus.confirmed,
        finding_type="poc")
    # Jump-to-source link for the PoC finding (located_in → src/httpd.c at the sink line).
    link_finding_to_source(session, project, finding_id=f_poc.id, tree=tree, rel="src/httpd.c", line=27)

    # 3) Static memory-safety vuln — code_present/static (the FLOOR).
    f_static = persist_finding(
        session, project_id=pid, target_id=httpd.id, task_id=_task(httpd, "static_analysis").id,
        finding=Finding(
            title="Stack buffer overflow in diagnostics() via strcpy",
            severity="high", confidence="medium", category="memory-safety",
            summary="diagnostics() copies an attacker-influenced `target` parameter into a 64-byte "
                    "stack buffer with strcpy — no bounds check.",
            reasoning="Observed strcpy(buf, tgt) where tgt derives from get_param(); buf is char[64]. "
                      "No runtime trigger attempted, so this is the static floor.",
            evidence=Evidence(function="diagnostics", sink="strcpy", file="/sbin/httpd",
                              address="0x401b20", decompiled_snippet=(
                                  "char buf[64];\n"
                                  "char *tgt = get_param(query, \"target\");\n"
                                  "strcpy(buf, tgt);  // unbounded\n"))),
        finding_type="vulnerability")
    link_finding_to_source(session, project, finding_id=f_static.id, tree=tree, rel="src/httpd.c", line=37)

    # 4) Argued-reachable vuln — input_reachable/static (the SSDP memcpy).
    ev4 = Evidence(function="ssdp_dispatch", sink="memcpy", file="/lib/libupnp.so", address="0x8c0",
                   extra={}).model_dump(exclude_none=True)
    A.upgrade_if_stronger(ev4, A.assurance(A.INPUT_REACHABLE, A.STATIC, A.UNAUTHENTICATED,
                                           detail="a source→sink path from the udp/1900 SSDP listener "
                                                  "to the memcpy is argued over the graph; not triggered"))
    persist_finding(
        session, project_id=pid, target_id=lib.id, task_id=_task(lib, "static_analysis").id,
        finding=Finding(
            title="Heap/stack overflow in ssdp_dispatch reachable from udp/1900",
            severity="high", confidence="medium", category="memory-safety",
            summary="ssdp_dispatch() memcpy's an attacker-supplied length straight from an SSDP packet "
                    "into a fixed buffer; the listener is unauthenticated on the LAN.",
            reasoning="A graph path argues reachability: udp/1900 socket → ssdp_dispatch → memcpy. "
                      "No live trigger yet, so the claim is input_reachable/static.",
            evidence=Evidence.model_validate(ev4)),
        finding_type="vulnerability")

    # 5) Info-leak — hardcoded credentials in the firmware.
    persist_finding(
        session, project_id=pid, target_id=fw.id, task_id=_task(fw, "pattern_sweep").id,
        finding=Finding(
            title="Hardcoded root credentials in /etc/shadow",
            severity="medium", confidence="high", category="hardcoded-secret",
            summary="The shipped /etc/shadow contains a crackable MD5-crypt root hash baked into "
                    "every unit of this firmware revision.",
            reasoning="String scan of the extracted rootfs surfaced an /etc/shadow entry with a "
                      "$1$ (MD5) root hash — a shared default across the fleet.",
            evidence=Evidence(file="/etc/shadow",
                              strings=["admin:$1$xyz$abcdef0123456789:0:0:root:/:/bin/sh"])),
        finding_type="vulnerability")

    # 6) Auth bypass — session check missing on a state-changing route.
    persist_finding(
        session, project_id=pid, target_id=web.id, task_id=_task(web, "static_analysis").id,
        finding=Finding(
            title="Auth bypass: /cgi-bin/diagnostics skips the session check",
            severity="high", confidence="medium", category="auth",
            summary="The diagnostics route is reachable without a valid session cookie, unlike the "
                    "rest of /api; it dispatches to the same vulnerable handler.",
            reasoning="Route table analysis shows /cgi-bin/* handlers are registered before the auth "
                      "middleware, so they bypass the session gate the /api routes enforce.",
            evidence=Evidence(file="/sbin/httpd", function="diagnostics",
                              extra={"assurance": A.assurance(A.CODE_PRESENT, A.STATIC, A.UNAUTHENTICATED)})),
        finding_type="vulnerability")

    # ── An instrumented rebuild (derived target) for the coverage-guided campaign ─────
    _step("Register an instrumented rebuild + run a mock fuzz campaign (offline)")
    httpd_instr = ingest_file(session, project, str(httpd_bytes), name="sbin/httpd (instrumented)",
                              parent=fw)
    _classify(httpd_instr, kind="executable", fmt="ELF", arch="x86_64",
              extra={"instrumented": True, "fuzz_target_sources": ["/src/httpd.c"],
                     "sanitizers": ["asan"], "coverage": "sancov"})
    # instrumented_build_of: the rebuilt target → the original it was rebuilt from.
    create_edge(session, project, src_kind="target", src_id=httpd_instr.id,
                dst_kind="target", dst_id=httpd.id, type="instrumented_build_of",
                attrs={"sanitizers": ["asan"], "coverage": "sancov"})
    # The instrumented target is built_from the same source tree.
    create_edge(session, project, src_kind="target", src_id=httpd_instr.id,
                dst_kind="source_tree", dst_id=tree.id, type="built_from",
                attrs={"system": "make", "instrumentation": "asan+sancov"})

    from hexgraph.engine import campaigns as C
    spec = FuzzCampaignSpec(target_id=httpd_instr.id, surface="source_lib", harness_source=HARNESS_C,
                            function="cgi_handler", target_sources=["/src/httpd.c"],
                            max_total_time=120)
    row = C.start_campaign(session, project, httpd_instr, spec=spec)
    # Drive the full lifecycle to completion (the mock launcher already wrote /out).
    C.reap_campaign(session, session.get(FuzzCampaign, row.id))
    session.flush()

    # ── Egress audit (a few allowed + one denied) ────────────────────────────────────
    _step("Record egress audit events (allowed + denied)")
    poc_task_id = f_poc.task_id
    record_egress(session, project_id=pid, target_id=web.id, task_id=poc_task_id,
                  dest="192.168.1.1:80", allowed=True, tool="web_poc",
                  detail="bounded local-network scope (private host, port 80)")
    record_egress(session, project_id=pid, target_id=web.id, task_id=poc_task_id,
                  dest="192.168.1.1:80", allowed=True, tool="http_request",
                  detail="login probe — bounded local-network scope")
    record_egress(session, project_id=pid, target_id=svc.id, task_id=None,
                  dest="192.168.1.1:5000", allowed=True, tool="tcp_probe",
                  detail="upnpd control banner grab (private host, port 5000)")
    record_egress(session, project_id=pid, target_id=web.id, task_id=poc_task_id,
                  dest="8.8.8.8:53", allowed=False, tool="http_request",
                  detail="blocked: destination is not loopback/private (egress refused)")

    session.flush()

    # ── Summary counts ───────────────────────────────────────────────────────────────
    counts = {
        "project_id": pid,
        "reused": False,
        "targets": session.query(Target).filter(Target.project_id == pid).count(),
        "nodes": session.query(Node).filter(Node.project_id == pid).count(),
        "edges": session.query(Edge).filter(Edge.project_id == pid).count(),
        "findings": session.query(FRow).filter(FRow.project_id == pid).count(),
        "campaigns": session.query(FuzzCampaign).filter(FuzzCampaign.project_id == pid).count(),
        "edge_types": sorted({e.type for e in
                              session.query(Edge).filter(Edge.project_id == pid).all()}),
    }
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed the HexGraph showcase project (mock, offline).")
    ap.add_argument("--reset", action="store_true", help="delete any prior showcase project first")
    args = ap.parse_args()

    # Enable the optional features the showcase exercises (fuzzing → Campaigns tab + the
    # coverage shading + the Fuzz button; network → the egress audit semantics). These
    # are written to settings.json under HEXGRAPH_HOME, picked up by `hexgraph serve`.
    from hexgraph import settings as st
    st.update_settings({
        "features.fuzzing.enabled": True,
        "features.poc.enabled": True,
        "features.network.enabled": True,
        "features.build.enabled": True,
    })

    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import session_scope

    prepare_database()
    with session_scope() as s:
        info = seed(s, reset=args.reset)

    print()
    if info.get("reused"):
        print(f"\033[33m↺ showcase project already exists\033[0m (id {info['project_id']}); "
              "pass --reset to rebuild it.")
    else:
        print("\033[32m✓ showcase seeded\033[0m — "
              f"{info['targets']} targets · {info['nodes']} nodes · {info['edges']} edges · "
              f"{info['findings']} findings · {info['campaigns']} campaign(s)")
        print(f"  edge types: {', '.join(info['edge_types'])}")
    print(f"  project id: {info['project_id']}")
    print("  serve it:   just serve   →  open the project in the UI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
