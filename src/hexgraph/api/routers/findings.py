"""Findings: read/triage/edit/verify, navigation components, follow-up spawning."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph.db.models import Edge, Finding, FindingStatus, Node, Project, Target, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.followups import spawn_followup
from hexgraph.engine.suggester import suggest_followups
from hexgraph.entitlements import require

from ._shared import BulkStatus, FindingPatch, StatusUpdate, finding_dict

router = APIRouter()


@router.get("/api/findings/{finding_id}")
def api_finding(finding_id: str):
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        task = s.get(Task, f.task_id)
        return {**finding_dict(f), "task_type": task.type if task else None}


@router.post("/api/findings/{finding_id}/status")
def api_set_finding_status(finding_id: str, body: StatusUpdate):
    try:
        new_status = FindingStatus(body.status)
    except ValueError:
        raise HTTPException(400, f"invalid status {body.status!r}")
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        f.status = new_status.value
        return {"id": f.id, "status": new_status.value}


@router.delete("/api/findings/{finding_id}")
def api_delete_finding(finding_id: str):
    """Permanently delete a finding (HARD delete — irreversible). Distinct from
    setting status='dismissed', which keeps the row, reversibly greyed. Cleans up
    every polymorphic reference (edges/annotations) so nothing dangles."""
    from hexgraph.engine.removal import delete_finding

    with session_scope() as s:
        if s.get(Finding, finding_id) is None:
            raise HTTPException(404, "finding not found")
        return delete_finding(s, finding_id)


@router.patch("/api/findings/{finding_id}")
def api_patch_finding(finding_id: str, body: FindingPatch):
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        # Light edit: stash the agent's original severity/confidence, mark edited.
        if (body.severity and body.severity != f.severity) or (body.confidence and body.confidence != f.confidence):
            ev = dict(f.evidence_json or {})
            extra = dict(ev.get("extra") or {})
            extra.setdefault("agent_original", {"severity": f.severity, "confidence": f.confidence})
            ev["extra"] = extra
            f.evidence_json = ev
            f.origin = "agent_edited"
        if body.severity:
            f.severity = body.severity
        if body.confidence:
            f.confidence = body.confidence
        if body.title:
            f.title = body.title
        if body.human_notes is not None:
            f.human_notes = body.human_notes
        if body.dismissed_reason is not None:
            f.dismissed_reason = body.dismissed_reason
        if body.status:
            try:
                f.status = FindingStatus(body.status).value
            except ValueError:
                raise HTTPException(400, f"invalid status {body.status!r}")
        if body.category is not None:
            f.category = body.category
        if body.summary is not None:
            f.summary = body.summary
        if body.reasoning is not None:
            f.reasoning = body.reasoning
        if body.evidence is not None:
            # Full evidence replace from the UI editor; the model validates the shape.
            from pydantic import ValidationError

            from hexgraph.models.finding import Evidence
            try:
                f.evidence_json = Evidence(**body.evidence).model_dump(exclude_none=True)
            except ValidationError as exc:
                raise HTTPException(400, f"invalid evidence: {exc.errors()[:3]}")
        return finding_dict(f)


@router.post("/api/findings/{finding_id}/verify")
def api_verify_finding(finding_id: str):
    """Re-run a PoC finding's stored spec (evidence.extra.poc) against its target and
    update the finding's verification in place. Lets an analyst confirm a PoC with one
    click — binary PoCs need features.poc, web PoCs need features.network."""
    from hexgraph.engine.poc import verify_poc as _verify
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        extra0 = (f.evidence_json or {}).get("extra") or {}
        spec = extra0.get("poc")
        fuzz = extra0.get("fuzz") or {}
        # A promoted fuzz crash (or any fuzz_crash) re-verifies by replaying its stored
        # CAS reproducer against the instrumented harness binary — the LLM-free crash
        # oracle. Prefer this when the poc spec is a fuzz_reproducer or absent but a
        # reproducer_ref exists; fall through to the generic verify_poc otherwise.
        use_reproducer = bool(fuzz.get("reproducer_ref")) and (
            not spec or spec.get("kind") == "fuzz_reproducer")
        if not spec and not use_reproducer:
            raise HTTPException(400, "this finding has no stored PoC spec to verify")
        # Resolve the PoC's OWN target, not blindly finding.target_id: a PoC may have been
        # authored/verified against a DIFFERENT target than the finding it's attached to
        # (e.g. a vuln finding on a parent binary whose exploit fires against a child/live
        # web surface). verify_poc records that as evidence.extra.poc_target_id. Prefer it;
        # fall back to finding.target_id when it's absent or the recorded target is gone.
        poc_target_id = extra0.get("poc_target_id")
        t = s.get(Target, poc_target_id) if poc_target_id else None
        if t is None:
            t = s.get(Target, f.target_id)
        try:
            if use_reproducer:
                from hexgraph.engine.poc import verify_finding_reproducer
                r = verify_finding_reproducer(s, s.get(Project, f.project_id), f)
            else:
                r = _verify(s, s.get(Project, f.project_id), t, spec)
        except PolicyViolation:
            raise HTTPException(403, "enable features.network (web PoC) or features.poc/fuzzing (binary/fuzz PoC) to verify")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, f"verification failed: {exc}")
        ev = dict(f.evidence_json or {})
        extra = dict(ev.get("extra") or {})
        # Preserve the original spec (with {{NONCE}} intact) so re-verify stays
        # repeatable; r.get("spec") is the nonce-substituted copy.
        if spec:
            extra["poc"] = spec
        # MERGE the engine-computed assurance via the partial order so a re-verify NEVER
        # DOWNGRADES an already-stronger stored rung: a failed/weaker re-verify (unconfirmed,
        # or an input_reachable/static argument) must not lower a code_present/dynamic or
        # input_reachable/dynamic claim. A genuine re-confirmation at the same/higher rung is
        # fine. (An earlier fix kept assurance from being DROPPED on re-verify; this guards the
        # related DOWNGRADE.) The triple is engine-derived, not caller-supplied.
        from hexgraph.engine.assurance import assurance_of, merge_assurance
        merged = merge_assurance(assurance_of(f.evidence_json), r.get("assurance"))
        extra["assurance"] = merged
        extra["verification"] = {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                                 "exit_code": r.get("exit_code"), "nonce": r.get("nonce"),
                                 "output": (r.get("output") or "")[:2000],
                                 "assurance": merged}
        # Refresh the human-facing reproduction command (the structured spec stays the
        # re-verify source of truth; this is a display rendering only).
        if spec:
            from hexgraph.engine.poc_repro import repro_command
            try:
                extra["repro_command"] = repro_command(spec, t)
            except Exception:  # noqa: BLE001
                pass
        ev["extra"] = extra
        f.evidence_json = ev
        return {**finding_dict(f), "verified": bool(r.get("verified")), "detail": r.get("detail")}


@router.get("/api/findings/{finding_id}/suggestions")
def api_finding_suggestions(finding_id: str):
    require("suggest.followups")  # no-op locally; the paid-feature gate
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        return [fu.model_dump(exclude_none=True) for fu in suggest_followups(f)]


@router.post("/api/findings/{finding_id}/followups/{index}")
async def api_spawn_followup(finding_id: str, index: int):
    from hexgraph.engine.worker import get_worker

    with session_scope() as s:
        try:
            task = spawn_followup(s, finding_id, index)
        except (ValueError, IndexError) as exc:
            raise HTTPException(404, str(exc))
        task_id, target_id = task.id, task.target_id
    await get_worker().enqueue(task_id)
    return {"task_id": task_id, "status": "queued", "target_id": target_id}


@router.get("/api/findings/{finding_id}/components")
def api_finding_components(finding_id: str):
    """The graph entities this finding is `about` (for highlight/navigation)."""
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        out = [{"kind": "target", "id": f.target_id, "role": "target"}]
        edges = s.query(Edge).filter(
            Edge.src_kind == "finding", Edge.src_id == finding_id
        ).all()
        for e in edges:
            entry = {"kind": e.dst_kind, "id": e.dst_id, "role": (e.attrs_json or {}).get("role")}
            if e.dst_kind == "node":
                n = s.get(Node, e.dst_id)
                if n is not None:
                    entry["label"] = n.name
                    entry["node_type"] = n.node_type
            out.append(entry)
        return out


@router.post("/api/findings/bulk-status")
def api_bulk_status(body: BulkStatus):
    try:
        new_status = FindingStatus(body.status)
    except ValueError:
        raise HTTPException(400, f"invalid status {body.status!r}")
    with session_scope() as s:
        updated = 0
        for fid in body.ids:
            f = s.get(Finding, fid)
            if f is not None:
                f.status = new_status.value
                updated += 1
        return {"updated": updated, "status": new_status.value}
