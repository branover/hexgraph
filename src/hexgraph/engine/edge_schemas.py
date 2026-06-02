"""Edge-type attribute schemas (which attributes make sense on which edge).

Edges are polymorphic and attributed (`edge.attrs_json`); this registry says what
attributes are *meaningful* for each edge type so callers (UI, MCP agents, API)
populate them consistently and `get_schemas` / `/api/edge-schemas` can advertise
them. It is **guidance, not a hard schema** — unknown keys are kept, missing ones
are fine — but list-valued attributes (e.g. a `calls` edge's `call_sites`) are
merged as sets so recording the same edge twice accumulates rather than clobbers.

Socket node attributes (`kind`/`port`/`name`/`bind_addr`) live on the socket NODE
(its identity); the code address where a listen/connect happens lives on the
`listens_on` / `connects_to` EDGE.
"""

from __future__ import annotations

from typing import Any

# A socket node's `kind` attribute.
SOCKET_KINDS = ("tcp", "udp", "unix", "io", "netlink", "raw", "other")


def _attr(desc: str, *, type: str = "string", list: bool = False) -> dict:
    return {"desc": desc, "type": type, "list": list}


# edge type -> {description, attributes: {name: {desc, type, list}}}
EDGE_ATTRIBUTE_SCHEMAS: dict[str, dict[str, Any]] = {
    "calls": {
        "description": "src (function or binary) calls dst (function).",
        "attributes": {
            "call_sites": _attr("hex addresses where the call occurs", type="hex", list=True),
            "count": _attr("number of call sites", type="int"),
            "arg_constraints": _attr(
                "general conclusions about argument values, e.g. "
                '[{"index":2,"name":"flags","conclusion":"always O_RDONLY"},'
                '{"index":3,"name":"len","conclusion":"<= 64"}]', type="object", list=True),
            "conditional": _attr("guard that gates the call, if any", type="string"),
        },
    },
    "listens_on": {
        "description": "src (binary/function) opens a LISTENING socket dst (server side).",
        "attributes": {
            "address": _attr("hex address where the bind/listen occurs", type="hex"),
            "backlog": _attr("listen() backlog if known", type="int"),
            "port": _attr("port (also on the socket node; repeat here for convenience)", type="int"),
            "reachable_preauth": _attr("does the listener accept data before auth?", type="bool"),
        },
    },
    "connects_to": {
        "description": "src (binary/function) CONNECTS to a socket dst (client side).",
        "attributes": {
            "address": _attr("hex address where the connect occurs", type="hex"),
            "port": _attr("port (also on the socket node)", type="int"),
        },
    },
    "reads": {
        "description": "src reads from dst (file/socket/buffer).",
        "attributes": {
            "address": _attr("hex address of the read", type="hex"),
            "size": _attr("bytes read / buffer size", type="int"),
            "field": _attr("which field/offset is read", type="string"),
        },
    },
    "writes": {
        "description": "src writes to dst (file/socket/buffer).",
        "attributes": {
            "address": _attr("hex address of the write", type="hex"),
            "size": _attr("bytes written", type="int"),
            "field": _attr("which field/offset is written", type="string"),
        },
    },
    "taints": {
        "description": "untrusted data flows from src into dst (source → sink).",
        "attributes": {
            "source": _attr("the untrusted source (e.g. 'stdin TMPL= field')"),
            "via_param": _attr("argument index/name the tainted value reaches", type="string"),
            "sanitized": _attr("any (incomplete) sanitization applied en route", type="string"),
        },
    },
    "bypasses": {
        "description": "attacker input defeats/weakens a control (auth/logic bugs).",
        "attributes": {
            "control": _attr("the control defeated (e.g. 'token comparison')"),
            "how": _attr("how it is defeated (e.g. 'empty token → strncmp len 0')"),
            "address": _attr("hex address of the check", type="hex"),
        },
    },
    "references": {
        "description": "src references dst (data/string/address xref).",
        "attributes": {"address": _attr("hex address of the reference", type="hex")},
    },
    "similar_to": {
        "description": "same/near code across binaries (n-day primitive).",
        "attributes": {"by": _attr("what matched, e.g. 'content_hash'"),
                       "score": _attr("similarity 0..1", type="float")},
    },
    "routes_to": {
        "description": "a web endpoint/route dispatches to its handler function (the "
                       "static↔dynamic bridge: dynamic surface → static binary).",
        "attributes": {"handler": _attr("the handler symbol the route maps to"),
                       "address": _attr("hex address of the dispatch, if known", type="hex")},
    },
    "built_from": {
        "description": "a target is built from a source_tree (target → source_tree). The "
                       "graph keeps the shipped binary and its source linked.",
        "attributes": {"subdir": _attr("subdirectory within the tree the target builds from")},
    },
    "located_in": {
        "description": "a finding/node is located in a source_file (finding|node → "
                       "node[source_file]). The jump-from-finding-to-source link.",
        "attributes": {"line": _attr("1-based line in the file", type="int"),
                       "col": _attr("1-based column, if known", type="int")},
    },
    "harnesses": {
        "description": "a harness exercises a target/function (node[harness] → "
                       "target|node). The harness's source is a role-tagged source_file.",
        "attributes": {"function": _attr("the function the harness drives, if focused")},
    },
    "instrumented_build_of": {
        "description": "a derived (instrumented) target is a rebuild OF the original "
                       "shipped target (target → target). Keeps 'the shipped binary' and "
                       "'our fuzzable rebuild' distinct but linked; the rebuild carries "
                       "SanCov+ASan for coverage-guided fuzzing.",
        "attributes": {
            "build_id": _attr("the build that produced this instrumented target"),
            "sanitizers": _attr("the sanitizers baked into the rebuild", list=True),
        },
    },
    "builds": {
        "description": "a build_spec produces a target/artifact (build_spec → target). "
                       "The recorded recipe that built the (instrumented) target.",
        "attributes": {"build_id": _attr("the build (execution) that produced the target")},
    },
}


def describe_edges() -> dict:
    """Serializable view for get_schemas / the API: per-type description + attrs."""
    out: dict[str, Any] = {}
    for etype, spec in EDGE_ATTRIBUTE_SCHEMAS.items():
        out[etype] = {
            "description": spec["description"],
            "attributes": {n: {"desc": a["desc"], "type": a["type"], "list": a["list"]}
                           for n, a in spec["attributes"].items()},
        }
    return out


def _list_attrs(edge_type: str) -> set[str]:
    spec = EDGE_ATTRIBUTE_SCHEMAS.get(edge_type, {})
    return {n for n, a in spec.get("attributes", {}).items() if a.get("list")}


def merge_edge_attrs(edge_type: str, existing: dict | None, new: dict | None) -> dict:
    """Merge `new` into `existing` for an edge of `edge_type`. List-typed attributes
    (per the schema) are unioned (order-preserving, deduped); everything else is
    overwritten by `new`. Unknown keys pass through."""
    merged = dict(existing or {})
    lists = _list_attrs(edge_type)
    for k, v in (new or {}).items():
        if k in lists:
            cur = list(merged.get(k) or [])
            incoming = v if isinstance(v, list) else [v]
            for item in incoming:
                if item not in cur:
                    cur.append(item)
            merged[k] = cur
        else:
            merged[k] = v
    return merged
