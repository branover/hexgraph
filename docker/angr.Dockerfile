# HexGraph angr image (design §3.5 + §4 Phase 5C, KEY DECISION D10 — a DEDICATED,
# OPTIONAL image, NEVER the shared hexgraph-sandbox). angr's pip stack (angr + z3 +
# the claripy/pyvex/cle/archinfo/ailment/unicorn chain) is the single heaviest
# dependency in Phase 5 and it is opt-in, so it ships in its OWN sibling image — like
# docker/fuzz.Dockerfile — instead of bloating the base sandbox every user builds and
# pulls. The base docker/sandbox.Dockerfile stays unchanged; only a target that the
# operator opted into solving (features.angr) ever runs in here.
#
# What it carries:
#   - angr — concolic / symbolic execution. The angr_probe drives it to solve for a
#     concrete input that REACHES a sink (the flagship answer) or recover a value that
#     SATISFIES a check, behind the get_solver() seam.
#   - z3-solver — the SMT solver angr asks for a satisfying model. Pinned alongside angr.
#   The angr-family deps (claripy/pyvex/cle/archinfo/ailment/unicorn/pyelftools) are
#   version-locked by angr's own metadata, so pinning angr pins them transitively.
#
# Build:  docker build -f docker/angr.Dockerfile -t hexgraph-angr:latest .  (context = repo root)
#         WORKTREE DISCIPLINE: for local testing build a PRIVATE tag and point the env
#         override at it — NEVER clobber the shared tag:
#           docker build -f docker/angr.Dockerfile -t hexgraph-angr:wt-phase5c .
#           export HEXGRAPH_ANGR_IMAGE=hexgraph-angr:wt-phase5c
#
# Run ONLY via sandbox/runner.py — the SAME hardening as every sandbox container:
# --network none, --read-only rootfs, tmpfs /scratch, --cap-drop ALL, --no-new-privileges,
# --user 1000, mem/cpu/pids caps (a ResourceSpec), a hard timeout. angr never EXECUTES the
# target — it symbolically explores the artifact's bytes and asks z3 for a model — so this
# image relaxes NO sandbox/exec/egress boundary; the features.angr gate exists only to make
# the heavy compute opt-in and bound it. A bigger image is NOT a weaker box. The angr_probe
# is MOUNTED from the install at run time — editing the probe needs no rebuild; only this
# toolchain change does.
# angr 9.2.214+ requires Python >= 3.12, so we base on the official slim Python 3.12 image
# (debian-bookworm under the hood) rather than debian:bookworm-slim, whose system Python is
# 3.11. The official python image is NOT externally-managed, so a plain `pip install` works.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# angr pulls native wheels (unicorn, z3, the VEX/capstone chain) that ship as manylinux
# wheels, so no compiler is needed at install time. `libgomp1` is the one runtime lib a few
# of those wheels dlopen; ca-certificates lets pip reach PyPI. Kept deliberately minimal.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin angr for reproducibility (design §2.7 — a heavy dependency must not drift silently).
# Pinning `angr` transitively pins its co-versioned family (claripy/pyvex/cle/archinfo/
# ailment) AND the exact z3-solver claripy requires, via angr's metadata — so we do NOT pin
# z3 separately (an independent pin only risks a resolver conflict). The import check fails
# the build loudly if a wheel or a native lib is missing (the dependency-present assertion).
ARG ANGR_VERSION=9.2.221
RUN pip install --no-cache-dir "angr==${ANGR_VERSION}" \
    && python3 -c "import angr, claripy, z3; print('angr', angr.__version__, '| z3', z3.get_version_string())"

# Bake the probe scripts into the image (mounted-over at run time, except NO_MOUNT mode).
COPY src/hexgraph/sandbox/probes/ /opt/hexgraph/

# Drop privileges: the angr probe runs as the unprivileged analyst (uid 1000), matching the
# runner's --user 1000. The target artifact is RO at /artifact; output (if any) only to /out.
RUN useradd --create-home --uid 1000 analyst
USER analyst

# angr writes a small amount of cache/state; HOME is set to a writable tmpfs by the runner
# (HOME=/scratch). Keep the entrypoint empty so the runner drives `python3 angr_probe.py`.
ENTRYPOINT []
CMD ["python3", "-c", "import angr; print(angr.__version__)"]
