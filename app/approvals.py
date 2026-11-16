"""Approval workflow for access requests, built on separation of duties.

Rules:
- The requester's line manager approves first.
- Sensitive requests then also need a system owner and a security review, both done by IT admins.
- Nobody can decide their own request.
- One person can only decide ONE step of a request.
- A rejection ends the request.
"""
import json

from app import db

LINE = "line manager"


class ApprovalError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _decisions(a):
    return json.loads(a["decisions"] or "{}")


def _required(a):
    return json.loads(a["required_approvers"])


def overall_status(a):
    d, req = _decisions(a), _required(a)
    if any(v["decision"] == "rejected" for v in d.values()):
        return "rejected"
    if all(step in d and d[step]["decision"] == "approved" for step in req):
        return "approved"
    return "pending"


def visible_to(user, a):
    if user["role"] == "it_admin":
        return True
    if user["role"] == "manager":
        return a["requester_manager"] == user["employee_id"]
    return False


def check(user, a, step):
    """Can this user decide this step right now? Returns (ok, reason)."""
    d = _decisions(a)
    if a["status"] != "pending":
        return False, "This request has already been decided."
    if step not in _required(a):
        return False, "That approval step is not needed for this request."
    if step in d:
        return False, "That step has already been decided."
    if a["requester_id"] == user["employee_id"]:
        return False, "You cannot decide your own request."
    if any(v["by"] == user["employee_id"] for v in d.values()):
        return False, "One person cannot decide more than one step of the same request."
    if step == LINE:
        if a["requester_manager"] != user["employee_id"]:
            return False, "Only the requester's line manager can decide this step."
    else:
        if user["role"] != "it_admin":
            return False, "Only IT administrators can decide this step."
        if LINE not in d or d[LINE]["decision"] != "approved":
            return False, "This step opens after the line manager approves."
    return True, ""


def present(a, viewer):
    d, req = _decisions(a), _required(a)
    steps = []
    for step in req:
        if step in d:
            state = d[step]["decision"]
        elif a["status"] != "pending":
            state = "closed"
        elif step != LINE and not (LINE in d and d[LINE]["decision"] == "approved"):
            state = "waiting"
        else:
            state = "pending"
        steps.append({
            "step": step, "state": state,
            "by": d.get(step, {}).get("by_name"), "note": d.get(step, {}).get("note", ""),
            "at": d.get(step, {}).get("at"),
        })
    return {
        "id": a["id"], "ticket_no": a["ticket_no"], "requester_id": a["requester_id"],
        "requester_name": a["requester_name"], "resource": a["resource"], "reason": a.get("reason", ""),
        "sensitive": bool(a["sensitive"]), "status": a["status"], "created_at": a["created_at"],
        "steps": steps,
        "available": [step for step in req if check(viewer, a, step)[0]],
    }


def decide(user, approval_id, step, decision, note=""):
    a = db.get_approval(approval_id)
    if a is None or not visible_to(user, a):
        raise ApprovalError("Approval not found.", 404)  # same answer whether it exists or not
    ok, reason = check(user, a, step)
    if not ok:
        raise ApprovalError(reason, 403)
    d = _decisions(a)
    d[step] = {
        "decision": "approved" if decision == "approve" else "rejected",
        "by": user["employee_id"], "by_name": user["name"],
        "note": (note or "")[:200], "at": db.now_iso(),
    }
    status = overall_status({**a, "decisions": json.dumps(d)})
    db.save_decision(approval_id, d, status)
    if status != "pending":
        db.set_ticket_status(a["ticket_no"], status)
    db.audit(user["employee_id"], "approval_decision", {
        "approval_id": approval_id, "ticket_no": a["ticket_no"], "step": step,
        "decision": d[step]["decision"], "result": status,
    })
    return present(db.get_approval(approval_id), user)
