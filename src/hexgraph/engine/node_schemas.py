"""Node-type attribute schemas — what each node type IS, when to create it, and which
attributes the researcher expects to see populated on it.

The companion to `edge_schemas.py`. Nodes are typed (`node.node_type`) with a free-form
`attrs_json`; this registry is the *contract* an agent reads (via `get_schemas`) so the
same analysis run twice converges on the same graph instead of varying. It is **guidance,
not a hard schema** — unknown attrs are kept — but every create_node call should populate
the `recommended` attributes for the type, and `use_when` keeps the type taxonomy crisp
(notably: do NOT mint a standalone `sink` node for a dangerous library call that is already
a `symbol`/`function` node — see below).
"""

from __future__ import annotations

from typing import Any


def _a(desc: str, *, type: str = "string", list: bool = False, recommended: bool = False) -> dict:
    return {"desc": desc, "type": type, "list": list, "recommended": recommended}


# node type -> {description, use_when, identity, attributes:{name:{desc,type,list,recommended}}}
NODE_ATTRIBUTE_SCHEMAS: dict[str, dict[str, Any]] = {
    "function": {
        "description": "A function/subroutine in a binary.",
        "identity": "(target, normalized name) — recon pre-materializes these with address=null; "
                    "create_node MERGES into the existing one (fills address, unions attrs).",
        "use_when": "Any routine you analyze. Always bind it to its target_id and give its address.",
        "attributes": {
            "summary": _a("one-line description of what the function does", recommended=True),
            "params": _a('parameters as [{"name","type","note"}] — note attacker-controllability',
                         type="object", list=True, recommended=True),
            "returns": _a("what it returns and the meaning of values"),
            "is_sink": _a("true if this function is a dangerous operation (system/exec/strcpy/…) — "
                          "set this INSTEAD of creating a separate `sink` node", type="bool"),
            "tainted_params": _a("indices/names of params that reach a dangerous use", list=True),
            # Always-welcome auto-enrichment facts (Phase O §5.4): a decompiler/function-list
            # observation fills these in place on an EXISTING function node, no LLM/user.
            "address": _a("entry-point address (hex) — filled by auto-enrichment", type="hex"),
            "prototype": _a("recovered C prototype/signature — filled by auto-enrichment"),
            "signature": _a("recovered signature (alias of prototype) — auto-enrichment"),
            "calling_convention": _a("recovered calling convention — auto-enrichment"),
            "demangled_name": _a("demangled name (C++) — auto-enrichment"),
            "param_count": _a("recovered parameter count — auto-enrichment", type="int"),
            "local_count": _a("recovered local-variable count — auto-enrichment", type="int"),
            "locals": _a("recovered locals — auto-enrichment", type="object", list=True),
        },
    },
    "symbol": {
        "description": "An imported/exported symbol (library function, global).",
        "identity": "(target, normalized name).",
        "use_when": "An import/export you reference — especially a dangerous libc call. A risky import "
                    "(system, popen, strcpy, sprintf, …) is THIS, with is_sink=true — not a `sink` node.",
        "attributes": {
            "kind": _a("import | export", recommended=True),
            "library": _a("providing library, e.g. libc", recommended=True),
            "is_sink": _a("true if it's a dangerous operation (the dataflow target of taints edges)",
                          type="bool", recommended=True),
        },
    },
    "string": {
        "description": "A notable string constant in a binary.",
        "identity": "(target, value hash).",
        "use_when": "A string that matters (format string, path, command template, secret-looking). "
                    "Don't mint nodes for every string — recon already samples them.",
        "attributes": {"value": _a("the full string value", recommended=True),
                       "note": _a("why it matters")},
    },
    "struct": {
        "description": "A data structure / type.",
        "identity": "(target, normalized name).",
        "use_when": "A struct whose layout matters to a bug (e.g. an overflowed record).",
        "attributes": {"fields": _a('[{"name","type","offset"}]', type="object", list=True),
                       "size": _a("total size in bytes", type="int")},
    },
    "input": {
        "description": "An untrusted INPUT source — where attacker-controlled data enters.",
        "identity": "(target, name).",
        "use_when": "The SOURCE end of a dataflow: an env var (QUERY_STRING), a request param, a CLI "
                    "arg, a socket read. The thing a `taints` edge starts FROM.",
        "attributes": {
            "source": _a("where it comes from, e.g. 'HTTP query param host' / 'env QUERY_STRING'",
                         recommended=True),
            "trust": _a("untrusted | preauth | postauth — preauth reachability raises severity"),
        },
    },
    "sink": {
        "description": "A dangerous-operation convergence point in a dataflow (the END a `taints` "
                       "edge points TO).",
        "identity": "(target, name).",
        "use_when": "ONLY when the dangerous point is NOT already a function/symbol node. For a known "
                    "library call (system/exec/strcpy/sprintf) DON'T create this — set is_sink=true on "
                    "the function/symbol node and draw taints → that node. Use `sink` for abstract "
                    "points (e.g. 'the shell command built at 0x401200').",
        "attributes": {
            "operation": _a("the dangerous operation, e.g. 'shell exec' / 'memcpy'", recommended=True),
            "why": _a("why reaching it is dangerous", recommended=True),
            "address": _a("hex address of the operation", type="hex"),
        },
    },
    "socket": {
        "description": "A network/IPC endpoint SHARED across binaries (a server listens_on it, a "
                       "client connects_to it — both resolve to one node).",
        "identity": "(project, kind, port|name) — target_id is null (cross-binary). Make it with "
                    "create_socket, not create_node.",
        "use_when": "Modeling the network map: a listening port or an IPC channel.",
        "attributes": {"kind": _a("tcp|udp|unix|io|netlink|raw|other", recommended=True),
                       "port": _a("port number", type="int"), "name": _a("path/name for unix/io"),
                       "bind_addr": _a("bind address, e.g. 0.0.0.0")},
    },
    "endpoint": {
        "description": "A web route on a dynamic surface (method + path).",
        "identity": "(target=web_app, 'METHOD /path').",
        "use_when": "Mapping a web surface — usually materialized by surface_recon. Link it to its "
                    "handler function with a routes_to edge and to its params with references edges.",
        "attributes": {"method": _a("HTTP method", recommended=True),
                       "path": _a("URL path", recommended=True),
                       "auth": _a("none | required | unknown — auth posture of the route",
                                  recommended=True)},
    },
    "param": {
        "description": "A request parameter of a web endpoint.",
        "identity": "(target=web_app, 'METHOD /path#name').",
        "use_when": "A parameter worth tracking (especially attacker-controlled). references-edged "
                    "from its endpoint; taints-edged toward a sink when it's the injection vector.",
        "attributes": {"endpoint": _a("the owning 'METHOD /path'", recommended=True),
                       "location": _a("query | body | header | cookie"),
                       "note": _a("e.g. 'reaches shell in /api/diag'")},
    },
    "hypothesis": {
        "description": "A research question/claim, evidenced by findings.",
        "identity": "a hypothesis node; prefer create_hypothesis + link_evidence over raw create_node.",
        "use_when": "Tracking a line of inquiry ('auth can be bypassed via short token').",
        "attributes": {"statement": _a("the claim", recommended=True), "rationale": _a("why you think so")},
    },
    "pattern": {
        "description": "A reusable vulnerability/code pattern matched across targets.",
        "identity": "(project, content_hash).",
        "use_when": "Generalizing a bug shape to sweep other binaries for it.",
        "attributes": {"signature": _a("what defines the pattern", recommended=True)},
    },
    "source_file": {
        "description": "A file in a managed source_tree (trusted source we possess — NOT a "
                       "hostile target). Materialized lazily on reference; harnesses/PoCs/"
                       "scripts are role-tagged source_files.",
        "identity": "(project, fq_name=`<tree_id>:<rel>`) — one node per file path in a tree.",
        "use_when": "Don't hand-create these — they're materialized when you link a finding to "
                    "source (link_finding_to_source) or import a tree. Browse with read_source_file.",
        "attributes": {
            "tree_id": _a("the source_tree this file belongs to", recommended=True),
            "rel": _a("path relative to the tree root", recommended=True),
            "role": _a("code | harness | poc | script | build_recipe | dictionary | corpus_seed",
                       recommended=True),
            "origin": _a("the tree's origin (upload|git|archive|extracted|scratch)"),
        },
    },
    "harness": {
        "description": "A fuzz harness — a logical harness backed by a source_file(role=harness) "
                       "and `harnesses`→ the target/function it exercises (supersedes the transient "
                       "evidence.decompiled_snippet).",
        "identity": "(project, fq_name=`harness:<tree_id>:<rel>`).",
        "use_when": "Created by harness_generation/promotion; reference it to drive fuzzing.",
        "attributes": {
            "tree_id": _a("the source_tree holding the harness source", recommended=True),
            "rel": _a("path of the harness source within the tree", recommended=True),
            "function": _a("the focused function the harness drives, if any", recommended=True),
        },
    },
}


def describe_nodes() -> dict:
    """Serializable view for get_schemas / the API: per-type description, use_when,
    identity, and attributes (flagging the recommended ones to populate)."""
    out: dict[str, Any] = {}
    for ntype, spec in NODE_ATTRIBUTE_SCHEMAS.items():
        out[ntype] = {
            "description": spec["description"],
            "use_when": spec.get("use_when", ""),
            "identity": spec.get("identity", ""),
            "recommended_attributes": [n for n, a in spec["attributes"].items() if a.get("recommended")],
            "attributes": {n: {"desc": a["desc"], "type": a["type"], "list": a["list"],
                               "recommended": a["recommended"]}
                           for n, a in spec["attributes"].items()},
        }
    return out


def recommended_attrs(node_type: str) -> list[str]:
    spec = NODE_ATTRIBUTE_SCHEMAS.get(node_type, {})
    return [n for n, a in spec.get("attributes", {}).items() if a.get("recommended")]
