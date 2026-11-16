"""Tools: the only code allowed to change data. Every call passes through the policy gate first."""
import secrets

from app import db, policy


def _mask_email(email):
    name, _, domain = email.partition("@")
    return f"{name[0]}***@{domain}"


def _create_ticket(user, params, decision):
    ticket_no = db.create_ticket(user["employee_id"], params["category"], params["summary"], "normal", "open")
    return {"ticket_no": ticket_no, "status": "open"}


def _report_phishing(user, params, decision):
    ticket_no = db.create_ticket(user["employee_id"], "phishing", params["description"], "high", "open")
    return {"ticket_no": ticket_no, "priority": "high", "status": "open"}


def _check_ticket_status(user, params, decision):
    t = db.get_ticket(params["ticket_no"])
    return {"ticket_no": t["ticket_no"], "category": t["category"], "status": t["status"], "priority": t["priority"]}


def _request_access(user, params, decision):
    ticket_no = db.create_ticket(
        user["employee_id"], "access", f"Access request: {params['resource']}", "normal", "pending_approval"
    )
    db.create_approval(
        ticket_no, user["employee_id"], params["resource"],
        decision.details["sensitive"], decision.details["approvers"], reason=params["reason"],
    )
    return {"ticket_no": ticket_no, "status": "pending_approval", "approvals_needed": decision.details["approvers"]}


def _reset_password(user, params, decision):
    emp = user["employee_id"]
    if decision.verdict == "needs_verification":
        code = f"{secrets.randbelow(10**6):06d}"
        db.store_otp(emp, code)
        db.record_reset_request(emp)
        # Demo only: a real system would email or text this. It is never returned to the AI.
        print(f"\n[DEMO EMAIL] One-time code for {emp}: {code} (valid for 5 minutes)\n")
        return {"status": "verification_code_sent", "sent_to": _mask_email(user["email"])}
    db.clear_otp(emp)
    db.audit(emp, "password_reset_link_issued", {})
    return {"status": "reset_link_sent", "sent_to": _mask_email(user["email"])}


def _escalate(user, params, decision):
    ticket_no = db.create_ticket(user["employee_id"], "other", params["reason"], "high", "escalated")
    return {"ticket_no": ticket_no, "status": "escalated_to_human"}


HANDLERS = {
    "create_ticket": _create_ticket,
    "report_phishing": _report_phishing,
    "check_ticket_status": _check_ticket_status,
    "request_access": _request_access,
    "reset_password": _reset_password,
    "escalate_to_human": _escalate,
}


def run_action(user, action, params):
    """The single entry point for any action the AI proposes."""
    decision = policy.evaluate(user, action, params)
    db.audit(
        user["employee_id"], "action_decision",
        {"action": action, "verdict": decision.verdict, "rule": decision.rule},
    )
    result = None
    if decision.verdict in ("allow", "needs_verification", "needs_approval"):
        result = HANDLERS[action](user, params, decision)
    return {"action": action, "verdict": decision.verdict, "rule": decision.rule,
            "message": decision.message, "result": result}
