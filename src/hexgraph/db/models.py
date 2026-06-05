"""SQLAlchemy models (SPEC §4). The graph is modeled relationally — no Neo4j.

Entities: project, target (self-referential parent_id tree), node (typed sub-file
entities — see NodeType: function/symbol/string/struct/hypothesis/pattern/input/
sink/socket), polymorphic attributed edge (see EdgeType — contains/calls/taints/
listens_on/connects_to/similar_to/…), task, finding. `NodeType`/`EdgeType` are
String columns so new vocab is zero-migration. All ids are UUID strings.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --- enums (mirror SPEC §4) ----------------------------------------------------


class LLMBackendName(str, enum.Enum):
    mock = "mock"
    anthropic = "anthropic"
    claude_code = "claude_code"


class TargetKind(str, enum.Enum):
    firmware_image = "firmware_image"
    executable = "executable"
    shared_library = "shared_library"
    web_app = "web_app"      # a dynamic HTTP(S) attack surface reached via a Channel (design-dynamic-surfaces.md)
    service = "service"      # a bare non-HTTP network listener (raw TCP/UDP) reached via a Channel — first-class fuzzable surface (design-dynamic-surfaces.md)
    remote = "remote"        # a live device reached over SSH/telnet — the live-remote tier (docs/dynamic-surfaces-rehosting-remote.md)
    unknown = "unknown"


# A *surface* target is a reachable surface reached via a Channel (web_app/service/remote),
# NOT bytes at rest: it has `path=""` and is described by `metadata_json["channel"]`. Byte
# tasks (recon over a file, decompile, binary PoC) must never run their byte path against
# one — they route to the surface-appropriate probe instead. (design-dynamic-surfaces.md)
SURFACE_KINDS = frozenset({TargetKind.web_app, TargetKind.service, TargetKind.remote})


class NodeType(str, enum.Enum):
    """Sub-file / conceptual node kinds (P1 materializes function/symbol/string;
    struct/hypothesis/pattern/task arrive in later phases)."""

    function = "function"
    symbol = "symbol"
    string = "string"
    struct = "struct"
    hypothesis = "hypothesis"
    pattern = "pattern"
    input = "input"      # an untrusted-input source (env/arg/recv) for taint paths
    sink = "sink"        # a dangerous operation reached by tainted data
    socket = "socket"    # a network/IPC endpoint (tcp/udp/unix/io) shared across binaries
    endpoint = "endpoint"  # a web route / RPC method on a dynamic surface (analogue of function)
    param = "param"        # a request field (query/body/header/cookie) — analogue of input
    source_file = "source_file"  # a file in a source_tree (role-tagged: code|harness|poc|script|…), lazily materialized
    harness = "harness"    # a fuzz harness (references a source_file), supersedes the transient evidence.decompiled_snippet
    task = "task"


class EdgeType(str, enum.Enum):
    """Canonical edge vocabulary (design §3.3). Stored as a string column (no DB
    CHECK constraint) so new types are zero-migration."""

    contains = "contains"
    links_against = "links_against"
    imports_symbol = "imports_symbol"
    exports_symbol = "exports_symbol"
    calls = "calls"
    references = "references"
    reads = "reads"
    writes = "writes"
    instance_of_pattern = "instance_of_pattern"
    similar_to = "similar_to"
    duplicate_of = "duplicate_of"
    derived_from = "derived_from"
    produced_by = "produced_by"
    confirms = "confirms"
    refutes = "refutes"
    supports = "supports"
    contradicts = "contradicts"
    about = "about"
    annotates = "annotates"
    dataflow_hint = "dataflow_hint"
    taints = "taints"          # untrusted data flows from src into dst (source→sink)
    bypasses = "bypasses"      # attacker input defeats/weakens a control (auth/logic bugs)
    listens_on = "listens_on"  # a binary/function opens a listening socket (server side)
    connects_to = "connects_to"  # a binary/function connects to a socket (client side)
    routes_to = "routes_to"    # a web endpoint/route dispatches to its handler function (static↔dynamic link)
    built_from = "built_from"  # a target is built from a source_tree (target → source_tree)
    located_in = "located_in"  # a finding/node is located in a source_file (finding|node → node[source_file], attrs={line,col})
    harnesses = "harnesses"    # a harness exercises a target/function (node[harness] → target|node)
    instrumented_build_of = "instrumented_build_of"  # a derived (instrumented) target → the original target it was rebuilt from
    builds = "builds"          # a build_spec produces a target/artifact (build_spec → target, attrs={build_id})
    fuzzed_by = "fuzzed_by"    # a target/harness is fuzzed by a campaign (target|node → fuzz_campaign)
    produced_artifact = "produced_artifact"  # a campaign produced a crash artifact/finding (fuzz_campaign → finding, attrs={kind,dedup_key})
    reproduces = "reproduces"  # a reproducer/finding reproduces a crash (finding → fuzz_campaign|finding)
    covers = "covers"          # a campaign reached a function (fuzz_campaign → node[function], coverage)
    related_to = "related_to"  # generic fallback (kept for back-compat)


# Edge endpoint kinds + provenance origins (plain strings in the DB).
# `source_tree`/`build_spec`/`fuzz_campaign` are polymorphic endpoint kinds for SQL
# entities that are NOT graph nodes (design §4.1/§4.5 D1/D7): `built_from`
# (target → source_tree), `builds` (build_spec → target), `fuzzed_by`
# (target|node → fuzz_campaign), `produced_artifact`/`covers` (fuzz_campaign → …).
# Source FILES are `node`s (node_type=source_file), so a finding→source_file
# `located_in` edge uses the existing `node` kind, not these.
EDGE_KINDS = ("target", "node", "finding", "task", "source_tree", "build_spec", "fuzz_campaign")
EDGE_ORIGINS = ("tool", "llm", "human", "derived")


class TaskStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    needs_triage = "needs_triage"


class FindingStatus(str, enum.Enum):
    # Single widened triage axis (design ruling #9). Stored as a String column.
    new = "new"
    triaging = "triaging"
    confirmed = "confirmed"
    dismissed = "dismissed"
    reported = "reported"


# --- tables --------------------------------------------------------------------


class Project(Base):
    __tablename__ = "project"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    llm_backend: Mapped[LLMBackendName] = mapped_column(
        Enum(LLMBackendName), default=LLMBackendName.mock
    )
    model_pref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    data_dir: Mapped[str] = mapped_column(Text)

    targets: Mapped[list["Target"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "target"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("target.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(300))
    path: Mapped[str] = mapped_column(Text)
    kind: Mapped[TargetKind] = mapped_column(Enum(TargetKind), default=TargetKind.unknown)
    format: Mapped[str | None] = mapped_column(String(100), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(100), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Soft removal: archived targets (and their nodes/findings) are hidden from the
    # graph/lists but never deleted (durable knowledge). Re-adding the same bytes
    # restores them. Cascades down the parent_id subtree.
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="targets")
    children: Mapped[list["Target"]] = relationship()


class SourceTree(Base):
    """A managed tree of trusted source we possess and (later) build — distinct
    from a `target` (hostile bytes the adversary reaches). Design §4.1 (D1): a
    project holds MULTIPLE independent source trees, each optionally linked to a
    target via a `built_from` edge.

    Storage (D2): files live on disk under the project data dir, indexed by a
    JSON `manifest_json` (a flat file listing — rel/size/role/origin); individual
    `source_file` *nodes* are materialized LAZILY on reference (mirrors
    engine/filesystem.py + engine/nodes.py), never one row per file. `root_rel` is
    derived from the data dir — never a trusted absolute path. `content_hash` is a
    tree hash over the manifest (cheap content identity), NOT a byte sha256."""

    __tablename__ = "source_tree"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    name: Mapped[str] = mapped_column(String(300))
    # upload | git | archive | extracted | scratch (extracted == firmware bytes:
    # untrusted-for-reading, build-only; surfaced read-only in the viewer).
    origin: Mapped[str] = mapped_column(String(16), default="upload")
    vcs_rev: Mapped[str | None] = mapped_column(String(80), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Editable trees (HexGraph-authored harness/poc/script roles) get revisions later
    # (Phase 7); imported/extracted source is read-only for reproducibility.
    editable: Mapped[bool] = mapped_column(default=False)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Soft removal, mirrors target.archived / node.archived.
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BuildSpec(Base):
    """A recorded, reproducible build recipe (design §2.1/§4.5 D-build, Phase 2).

    A `BuildSpec` turns a `source_tree` into an instrumented artifact via an
    explicit, recorded recipe the API/tool layer executes in the sandbox — the
    `Builder` seam never runs a human-typed shell. Reproducibility is the contract:
    `recipe_sha` = sha256 over {phases, env, base_image, instrumentation, arch}; the
    same recipe_sha + same source `content_hash` + same `toolchain_digest` ⇒ the
    same build. The recipe lives here (durable, editable, auditable); each execution
    is a `Build` row (the ledger). All vendored/offline this phase: the build phase
    runs `--network none` (the audited fetch tier is Phase 7)."""

    __tablename__ = "build_spec"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    source_tree_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(300), default="build")
    # make | cmake | autotools | meson | cargo | go | custom
    system: Mapped[str] = mapped_column(String(20), default="make")
    # The recorded recipe: ordered explicit-argv phases, the instrumentation
    # profile, captured-artifact rel paths, NON-secret env, arch, base image,
    # network ("none" this phase), timeout. All in the envelope (no schema churn).
    recipe_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    instrumentation_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    artifacts_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    base_image: Mapped[str] = mapped_column(String(120), default="hexgraph-build:latest")
    arch: Mapped[str] = mapped_column(String(32), default="x86_64")
    network: Mapped[str] = mapped_column(String(8), default="none")
    # sha256 over {phases, env, base_image, instrumentation, arch} — the recipe identity.
    recipe_sha: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Build(Base):
    """One execution of a `BuildSpec` — the durable build ledger (design §4.5).

    Records status, the reproducibility triple (recipe_sha / source_content_hash /
    toolchain_digest), the produced artifacts as CAS shas, the full build log in CAS,
    timing, and any error. A build is durable + reproducible + auditable: nothing is
    re-run silently, and a malicious `configure` that burns CPU and exits leaves only
    this row + its log, never persistence or exfiltration (`--network none`, RO
    source, ephemeral container)."""

    __tablename__ = "build"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    build_spec_id: Mapped[str] = mapped_column(String(36), index=True)
    source_tree_id: Mapped[str] = mapped_column(String(36), index=True)
    # queued | building | succeeded | failed
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    recipe_sha: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    toolchain_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # rel path → CAS sha of the captured artifact bytes.
    artifacts_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # The full build log (stdout+stderr of every phase), stored in CAS.
    log_cas: Mapped[str | None] = mapped_column(String(64), nullable=True)
    instrumentation_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    returncode: Mapped[int | None] = mapped_column(nullable=True)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The derived target this build registered (the instrumented rebuild), if any.
    derived_target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Phase 7 — supply-chain provenance + determinism (the DB envelope, not the frozen
    # finding schema). `lockfile_json` is the hash-pinned dependency lockfile produced by
    # the bounded fetch phase (or {} for a vendored/offline build); `sbom_json` is the
    # SBOM-lite (fetched dep urls + sha256). `reproducible` is the reproducibility-badge
    # verdict (recipe_sha + source_content_hash + toolchain_digest + a lockfile digest all
    # recorded ⇒ replayable). `cache_hit` is True when this build REUSED a prior CAS
    # artifact for the same reproducibility key (skipped the rebuild). `source_revision_id`
    # records when a build was launched from a specific editable-IDE revision.
    lockfile_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sbom_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    reproducible: Mapped[bool] = mapped_column(default=False)
    cache_hit: Mapped[bool] = mapped_column(default=False)
    source_revision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # The reproducibility cache key (recipe_sha|source_content_hash|toolchain_digest|
    # lockfile_digest) — indexed so a later build can find a prior identical build to reuse.
    cache_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceRevision(Base):
    """One revision of an editable source file (design §6.2 D-edit, Phase 7).

    The editable IDE never mutates a file in place: a save writes a NEW `SourceRevision`
    (origin=`analyst-edit`, the full new content in CAS + a diff against the prior
    revision), so the edit history is durable + reversible and a build can be launched
    `rebuild-from-revision`. Only HexGraph-AUTHORED / role-tagged files in an EDITABLE
    tree (harness/poc/script/build_recipe + scratch) get revisions; imported/extracted/
    vendor source stays read-only (editing it would break the content_hash build
    contract). The file's working-tree bytes always equal its latest revision."""

    __tablename__ = "source_revision"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    source_tree_id: Mapped[str] = mapped_column(String(36), index=True)
    rel: Mapped[str] = mapped_column(String(400), index=True)
    # Monotonic per (tree, rel): 1, 2, 3, … (the latest is the working-tree content).
    seq: Mapped[int] = mapped_column(default=1)
    role: Mapped[str] = mapped_column(String(20), default="code")
    # The full file content at this revision, content-addressed in CAS.
    content_cas: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size: Mapped[int] = mapped_column(default=0)
    # A unified diff against the prior revision (display only; the content_cas is canonical).
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    # upload | import | analyst-edit | backfill (who/what produced this revision).
    origin: Mapped[str] = mapped_column(String(16), default="analyst-edit")
    note: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FuzzCampaign(Base):
    """A long-lived fuzzing campaign — the durable identity that makes fuzzing
    *progressive* (design §4.5 D7, §5.5). A campaign OUTLIVES a single task tick: it
    is start/stop/resume-able and accumulates corpus/coverage/dedup across runs. A
    detached, hardened sandbox container (owned by `container_name`) runs the fuzzer
    in continuous mode, streaming artifacts/stats to `/out`; a periodic reaper polls
    + ingests them. The launching `task` records `campaign_id`; status polling reads
    this row. Crash-safe: because the container is detached and this row durable, a
    `serve` restart re-attaches the reaper by `container_name`.

    `resources_json` carries the per-campaign ResourceSpec ceilings (mem/cpu/pids/
    tmpfs/timeout/unconstrained) — a RESOURCE knob, never a policy/gate relaxation."""

    __tablename__ = "fuzz_campaign"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    # The (usually instrumented, derived) target under test.
    target_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(300), default="campaign")
    # source_lib | binary_only | network | file_format (the attack SURFACE, design §2.3).
    surface: Mapped[str] = mapped_column(String(20), default="source_lib")
    # libfuzzer | afl (the engine selected for the surface; never branched on in task code).
    engine: Mapped[str] = mapped_column(String(20), default="libfuzzer")
    # The managed harness node (source_file role=harness), if any.
    harness_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # The build_spec whose instrumented rebuild this campaign fuzzes, if any.
    build_spec_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # The launching task (for provenance / re-attach).
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # The detached container's durable name — the re-attach handle (crash-safe).
    container_name: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    # The host bind-mount the reaper polls for streamed artifacts/stats.
    outdir: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Stop parameters, instrumentation flags, seeds/dict refs, etc. (the campaign config).
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # The per-campaign ResourceSpec (mem/cpu/pids/tmpfs/timeout/unconstrained).
    resources_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # CAS refs for the preserved corpus / dictionary / coverage report (resumable).
    corpus_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dictionary_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    coverage_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # queued | building | running | paused | stopped | completed | failed
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    # Live stats the reaper updates: {execs, edges_covered, crash_count, peak_rss, last_run_at}.
    stats_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # AFL++ master + N secondaries (host-cores, capped). 1 for libFuzzer.
    instances: Mapped[int] = mapped_column(default=1)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FuzzArtifact(Base):
    """One deduplicated artifact a campaign produced — a crash/hang/leak/oom/corpus
    (design §4.5 D8). The reproducer BYTES live in CAS (`content_cas`), not here; this
    row is the queryable lifecycle record. `dedup_key` is the normalized stack hash
    (Phase-0), `UNIQUE(campaign_id, dedup_key)` so a campaign keeps ONE representative
    per bucket (the UI shows '1 representative + N dupes'). A crash artifact streams to
    a `fuzz_crash` finding (`finding_id`) whose minimized reproducer is re-runnable via
    the existing `verify_poc(reproducer_ref)` path."""

    __tablename__ = "fuzz_artifact"
    __table_args__ = (
        Index("ix_fuzz_artifact_campaign_dedup", "campaign_id", "dedup_key", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    campaign_id: Mapped[str] = mapped_column(String(36), index=True)
    # crash | hang | leak | oom | corpus
    kind: Mapped[str] = mapped_column(String(16), default="crash")
    # The (minimized) reproducer's CAS sha — the bytes, content-addressed (re-runnable).
    content_cas: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size: Mapped[int] = mapped_column(default=0)
    sanitizer: Mapped[str | None] = mapped_column(String(40), nullable=True)   # the ASan crash kind
    dedup_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dupe_count: Mapped[int] = mapped_column(default=0)
    faulting_function: Mapped[str | None] = mapped_column(String(300), nullable=True)
    exploitability_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # The fuzz_crash finding this artifact produced (nullable for a corpus artifact).
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FuzzEnvironment(Base):
    """A registered fuzz environment — a place a campaign's container can run (design
    §5.8b, Phase 6). `local` (the host Docker daemon, always implicit) plus N user-owned
    REMOTE Docker endpoints reached via DOCKER_HOST (ssh:// over an SSH control socket,
    or tcp:// + TLS client certs). A campaign SELECTS an environment (defaulting `local`).

    This row holds ONLY NON-SECRET metadata: a stable id, a human label, a non-secret
    `host_descriptor` (e.g. 'ssh://fuzzbox' or 'tcp://10.0.0.5:2376' — shown in the UI for
    identification), the transport, and a per-environment `ResourceSpec` CEILING the
    campaign inherits. The SECRET connection details (the full DOCKER_HOST string, SSH
    key/password, TLS certs) are NEVER stored here — they are read at connect time from
    env/config.toml KEYED BY THIS ENVIRONMENT'S `id`, exactly like the SSH/telnet remote
    creds (config.py / engine/remote.py). `last_health_json` caches the last health-check
    result (reachable/authorized/image-present) for the Settings indicator — also
    non-secret. Environments are HOST-level (not per-project): a registered remote box
    serves every project, so there is no project_id."""

    __tablename__ = "fuzz_environment"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(120), default="remote")
    # ssh | tcp | local
    transport: Mapped[str] = mapped_column(String(8), default="ssh")
    # A NON-SECRET descriptor for the UI/audit (NOT the full DOCKER_HOST when it carries
    # an embedded credential — but ssh://user@host / tcp://host:port are safe to show).
    host_descriptor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The per-environment ResourceSpec CEILING the campaign inherits
    # (mem/cpus/pids/tmpfs/timeout/unconstrained).
    resources_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Cached last health-check (non-secret): {ok, reachable, authorized, image_present,
    # docker_version, checked_at, detail}.
    last_health_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Node(Base):
    """A sub-file / conceptual node (function, symbol, string, ...). Distinct from
    `target` (artifacts with bytes). Identity is content-addressed via
    `content_hash` where available; `fq_name`/`address` are locators."""

    __tablename__ = "node"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    node_type: Mapped[str] = mapped_column(String(32), index=True)
    # The artifact this node lives in (nullable for cross-artifact concepts e.g. pattern).
    target_id: Mapped[str | None] = mapped_column(ForeignKey("target.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(300))
    fq_name: Mapped[str | None] = mapped_column(String(400), nullable=True)
    address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    attrs_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(32), default="recon")
    # Soft removal: an archived node (and the edges touching it) is hidden from the
    # graph/search; re-adding the same node (get_or_create_node) un-archives it and
    # its edges reappear (they are never deleted). Mirrors target.archived.
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Edge(Base):
    """One polymorphic, typed, attributed relationship between any two graph
    entities (target | node | finding | task)."""

    __tablename__ = "edge"
    # Composite indexes for the polymorphic endpoint lookups (created in migrations);
    # declared here so create_all matches a migrated DB. The single-column src_id/
    # dst_id indexes below (index=True) additionally serve edges_touching(), which
    # filters on an id alone (no project_id) and so can't use the composite ones.
    __table_args__ = (
        Index("ix_edge_src", "project_id", "src_kind", "src_id"),
        Index("ix_edge_dst", "project_id", "dst_kind", "dst_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    # Polymorphic endpoints — kinds in EDGE_KINDS; ids reference target/node/finding/task.
    src_kind: Mapped[str] = mapped_column(String(16))
    src_id: Mapped[str] = mapped_column(String(36), index=True)
    dst_kind: Mapped[str] = mapped_column(String(16))
    dst_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    directed: Mapped[bool] = mapped_column(default=True)
    # Typed attribution (queryable; required for server-side filtering).
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    origin: Mapped[str] = mapped_column(String(16), default="tool")  # EDGE_ORIGINS
    created_by_task_id: Mapped[str | None] = mapped_column(ForeignKey("task.id"), nullable=True)
    created_by_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attrs_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Task(Base):
    __tablename__ = "task"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    type: Mapped[str] = mapped_column(String(50))
    # The thing this task interrogates (P3): NODE|EDGE|SELECTION|HYPOTHESIS|TARGET.
    # `target_id` stays the resolved primary target the sandbox/decompiler operate on.
    anchor_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)  # None == "target"
    anchor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    objective_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Free-form task params (e.g. {"mock_scenario": ..., "function": ..., "sink": ...}).
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # The frozen context this task ran on (P2). Plain id (app-level provenance).
    context_bundle_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[TaskStatus] = mapped_column(Enum(TaskStatus), default=TaskStatus.queued)
    backend: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cost_estimate: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    log_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Set when this task was spawned from a finding's suggested follow-up.
    parent_finding_id: Mapped[str | None] = mapped_column(ForeignKey("finding.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    """Persisted finding = the schema payload (evidence/followups/refs as JSON)
    plus the envelope (ids, status, timestamp)."""

    __tablename__ = "finding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    task_id: Mapped[str] = mapped_column(ForeignKey("task.id"))

    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(40))
    summary: Mapped[str] = mapped_column(Text)
    reasoning: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    suggested_followups_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    related_target_refs_json: Mapped[list[Any]] = mapped_column(JSON, default=list)

    # Classifies the finding for sort/filter (vulnerability | recon | harness |
    # fuzz_crash | poc | annotation | other). DB envelope, not the frozen schema.
    finding_type: Mapped[str] = mapped_column(String(24), default="vulnerability", index=True)
    # String column (no CHECK) so the triage vocabulary can widen without migration pain.
    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.new.value)
    # HITL envelope (design §8): provenance + supersession + human edits.
    origin: Mapped[str] = mapped_column(String(16), default="agent")  # agent|human|agent_edited
    dismissed_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    supersedes_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    human_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Annotation(Base):
    """Human/agent annotation on a graph entity (P6): rename | note | tag | type_decl.
    Keyed by (node_kind, node_id) over target|node|finding. Confirmed renames apply
    to the node's display name; confirmed renames/notes feed back into agent context."""

    __tablename__ = "annotation"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    node_kind: Mapped[str] = mapped_column(String(16))   # target | node | finding
    node_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(16))        # rename | note | tag | type_decl
    value: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(16), default="human")     # human | agent_proposed
    status: Mapped[str] = mapped_column(String(16), default="confirmed")  # proposed | confirmed | rejected
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ContextBundle(Base):
    """A frozen, content-addressed context assembled for one task run (P2)."""

    __tablename__ = "context_bundle"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    bundle_sha: Mapped[str] = mapped_column(String(64), index=True)
    assembler_version: Mapped[str] = mapped_column(String(20), default="1")
    token_estimate: Mapped[int] = mapped_column(default=0)
    token_budget: Mapped[int] = mapped_column(default=0)
    item_count: Mapped[int] = mapped_column(default=0)
    dropped_count: Mapped[int] = mapped_column(default=0)
    deps_json: Mapped[list[Any]] = mapped_column(JSON, default=list)  # dependency fingerprints (staleness)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ContextItem(Base):
    __tablename__ = "context_item"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    bundle_id: Mapped[str] = mapped_column(ForeignKey("context_bundle.id"), index=True)
    order_index: Mapped[int] = mapped_column(default=0)
    kind: Mapped[str] = mapped_column(String(40))
    src_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
    src_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    content_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)  # CAS sha
    preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    est_tokens: Mapped[int] = mapped_column(default=0)
    priority: Mapped[int] = mapped_column(default=0)
    included: Mapped[bool] = mapped_column(default=True)


class AnalysisRun(Base):
    """Groups one task execution's inputs + outputs so runs over the same anchor
    are comparable (run-to-run finding diff)."""

    __tablename__ = "analysis_run"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    anchor_kind: Mapped[str] = mapped_column(String(16), default="target")
    anchor_id: Mapped[str] = mapped_column(String(36), index=True)
    task_id: Mapped[str] = mapped_column(String(36))
    task_type: Mapped[str] = mapped_column(String(50))
    backend: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    bundle_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Observation(Base):
    """A durable, content-addressed record of one deterministic tool call (Phase O,
    design §5.2). The Observation store is the substrate's home for "results that
    aren't promoted yet": every decompile/list/xref/taint/strings/structs call writes
    one, so a later agent or user can mine prior analysis instead of re-running it.

    Observations are NOT graph nodes — that would re-create the program-model
    explosion the curated graph deliberately avoids. The tie to the graph is
    bidirectional *by reference*: a node/edge/finding enriched from a call carries
    `attrs.provenance = [observation_id, …]`; the Observation carries `node_refs`
    back to what it was about. The full payload lives in CAS (`result_cas`), so large
    outputs don't bloat the DB and identical re-runs dedup."""

    __tablename__ = "observation"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    # Always scoped to a target (a decompilation is *of* a specific binary).
    target_id: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Who/what produced it: an agent-task id, an MCP session label, or "user-ui".
    source: Mapped[str] = mapped_column(String(64), default="")
    tool: Mapped[str] = mapped_column(String(64), index=True)
    args_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # the call, normalized
    # sha256 of the analyzed bytes — scopes/invalidates facts to the exact binary.
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # String column (zero-migration vocab, like NodeType): decompilation | function_list
    # | call_graph | xrefs | taint | strings | structs | gadgets | …
    result_kind: Mapped[str] = mapped_column(String(40), index=True)
    result_cas: Mapped[str | None] = mapped_column(String(64), nullable=True)  # full payload in CAS
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="ok")  # ok | error
    size: Mapped[int] = mapped_column(default=0)  # payload bytes stored in CAS
    # The function/struct/address the call was *about* — back-refs for navigation.
    node_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)


class EnrichmentFact(Base):
    """A distilled, always-welcome fact extracted from an Observation at write time,
    keyed by canonical node identity so a node added LATER can pull waiting facts with
    one indexed lookup instead of rescanning every Observation (Phase O, design §5.5).

    In Phase O (PR 1 of 3) the table + model exist but are NOT populated — the
    extractor registry and the join-at-`get_or_create_node` lifecycle land in PR 2.
    The table ships now so the program keeps its one-migration promise.

    `subject_key` is the SAME identity `engine.nodes.get_or_create_node` computes:
    `engine.nodes.normalize_symbol_name` for a name subject, the address for an
    address subject, and the ordered endpoint pair for a relationship (`pair`)."""

    __tablename__ = "enrichment_fact"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    target_id: Mapped[str] = mapped_column(String(36))
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject_kind: Mapped[str] = mapped_column(String(16))  # name | address | pair
    subject_key: Mapped[str] = mapped_column(String(255))
    node_type: Mapped[str] = mapped_column(String(40))     # the kind the fact applies to
    fact_kind: Mapped[str] = mapped_column(String(40))     # String vocab (zero-migration)
    fact_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_observation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_enrichment_fact_subject", "target_id", "node_type", "subject_kind", "subject_key"),
    )


class EgressEvent(Base):
    """Audit record for every outbound network action against a live target. Mandatory
    once the bounded-egress (local-network) tier is enabled — a durable, queryable log
    of what HexGraph connected to, when, and whether the policy allowed it
    (docs/design/design-dynamic-surfaces.md)."""

    __tablename__ = "egress_event"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    dest: Mapped[str] = mapped_column(String(255))          # host:port the action targeted
    allowed: Mapped[bool] = mapped_column(default=False)    # did the policy/allowlist permit it
    tool: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
